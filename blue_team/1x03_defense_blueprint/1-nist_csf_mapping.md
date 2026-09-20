# MedDefense Health Systems  
## NIST Cybersecurity Framework 2.0 — Current Profile

### Assessment Basis

This Current Profile applies the four required maturity levels—Not Implemented, Partial, Managed, and Optimized—to the six NIST CSF 2.0 functions: Govern, Identify, Protect, Detect, Respond, and Recover. The assessment distinguishes between work completed during Projects 1x00–1x02 and security capabilities that MedDefense itself operates as repeatable organizational processes. NIST CSF 2.0 defines these functions as the foundation for governance, risk identification, safeguards, detection, incident response, and recovery.

The six-month targets below are capability targets rather than authorization for additional unbudgeted spending. Any implementation must remain within MedDefense's fixed **$120,000 annual security budget** or explicitly displace lower-priority work.

---

# 1. GOVERN (GV)

**Current Level: Partial**

### Evidence

MedDefense has some elements of cybersecurity governance, but they are incomplete and uneven. Security responsibilities can be inferred from existing IT, Security, Biomedical Engineering, Clinical Operations, Finance, and application-owner roles, and the organization has a security awareness program, password policies, risk-treatment decisions, and an established annual security budget. These elements demonstrate that cybersecurity is not completely unmanaged.

However, the assessment does not establish a comprehensive, documented cybersecurity strategy containing formal risk appetite and risk-tolerance statements, recurring executive oversight, enterprise-wide policy governance, or a mature cybersecurity supply-chain risk-management process. More importantly, **GAP-011** identifies the absence of an enterprise vulnerability and patch-management program, while **GAP-012** identifies the absence of a formal enterprise incident-response and recovery coordination process. These are governance failures because the organization has not consistently established who must act, under what rules, within what timeframes, and with what oversight.

The consequences are visible in Project 1x02. For example, Finding 004 documents a Windows XP MRI workstation containing multiple weaponized remote-code-execution vulnerabilities, while Finding 001 identifies an unauthenticated Apache vulnerability on a billing server that had already suffered previous compromise. Threat Scenario 1 shows how an unremediated vulnerability can become the first stage of an enterprise ransomware incident, explicitly linking the attack to GAP-011.

**Risk Traceability:**  
**GAP-011 / GAP-012 → Finding 001 or Finding 004 → Threat Scenario 1, Operation Flatline.**

### Key Gaps

The most significant Govern gap is the absence of a **formal, enterprise cybersecurity risk-management system** that translates identified risks into documented policy, assigned accountability, remediation deadlines, exceptions, executive oversight, and recurring review.

MedDefense currently makes security decisions, but the evidence shows that those decisions have historically been inconsistent and reactive. Critical systems have remained vulnerable, response processes are not formalized, and security requirements are not consistently enforced across clinical, administrative, medical-device, and third-party environments.

### Target Level: Managed

Within six months, MedDefense should reach **Managed** maturity for Govern. The organization should have documented cybersecurity governance covering risk ownership, vulnerability-management timelines, incident-response authority, exception approval, medical-device/vendor risk, policy review, and executive oversight.

Managed is appropriate rather than Optimized because six months is sufficient to establish repeatable governance but not to demonstrate a long history of metrics-driven continuous improvement. The target directly addresses the governance conditions that allowed GAP-011 and GAP-012 to persist and therefore reduces the probability that known technical risks remain unresolved because no formal organizational mechanism requires action.

---

# 2. IDENTIFY (ID)

**Current Level: Partial**

### Evidence

Projects 1x00–1x02 significantly improved MedDefense's understanding of its environment. The formal Asset Registry originally contained **56 records**, and two subsequently identified shadow-IT assets increased the assessment-wide inventory to:

**56 existing records + 2 subsequently identified assets = 58 identified asset records.**

The project also identified critical assets, Restricted data, vulnerabilities, attack surfaces, gaps, threat actors, kill chains, and threat scenarios. This means MedDefense now possesses substantially more risk information than it had at the beginning of the assessment.

However, this work does not demonstrate that MedDefense previously maintained a comprehensive, reconciled, continuously managed asset inventory. The Asset Registry explicitly states that endpoint counts remain approximate, some powered-off systems may not have been discovered, ownership is unknown for multiple assets, and MedDefense still lacks a completely reconciled source of truth. The scan found unmanaged systems including `UNKNOWN-01` and a Westside Linux device that were not represented in prior organizational documentation.

Project 1x02 reinforces this weakness. Finding 028 identifies an unmanaged Linux/Jupyter/Cockpit server on the server network, while Finding 029 identifies an undocumented Grafana system with a publicly exploitable vulnerability. These findings show that asset identification has historically been an assessment activity rather than a mature continuous organizational process.

GAP-011 further establishes that MedDefense lacks an enterprise vulnerability-management lifecycle capable of routinely identifying, prioritizing, remediating, and verifying exposures. Threat Scenario 1 demonstrates why that matters: an attacker only needs one missed or unremediated exposed system to establish the initial foothold before enumerating the rest of the internal environment.

**Risk Traceability:**  
**GAP-011 → Finding 028 / Finding 029 → Threat Scenario 1.**

### Key Gaps

The primary Identify gap is that asset and risk identification are **not yet institutionalized as continuous, repeatable processes**. The assessment discovered assets and risks successfully, but MedDefense must now maintain that information after the project ends.

Specific deficiencies include unreconciled asset counts, unmanaged shadow IT, incomplete ownership information, inconsistent vulnerability management, and limited evidence that lessons learned from incidents routinely feed back into risk assessment.

### Target Level: Managed

MedDefense should reach **Managed** maturity for Identify within six months.

The 1x00–1x02 project outputs provide the starting dataset, so the principal six-month objective is not to rebuild the inventory. It is to operationalize it: assign owners, reconcile discovered assets, establish an approved source of truth, schedule recurring discovery and vulnerability assessments, track exceptions, and formally reassess risks when systems or threats change.

This target is justified because the organization already possesses the core information required for a Managed program; the missing capability is repeatable maintenance and governance.

---

# 3. PROTECT (PR)

**Current Level: Partial**

### Evidence

MedDefense has numerous protective controls. Existing safeguards include perimeter filtering, VPN controls, password requirements, account lockout, Sophos protection on most managed Windows workstations, hardened SSH on `ehr-srv-01`, nightly backups for selected systems, physical access controls, UPS protection, and security awareness training. The organization therefore clearly exceeds the Not Implemented level.

However, protection is inconsistent across the assets with the greatest clinical and enterprise impact. The posture assessment concludes that none of MedDefense's five most critical asset groups is well protected: EHR and Active Directory are only partially protected, while PACS/MRI, the network core, and Medical IoT are under-protected.

The vulnerability assessment demonstrates the scale of the control weakness. Final triage identified:

**6 Actionable Critical + 18 Actionable Standard = 24 actionable findings.**

Examples include:

- Finding 003: EHR PostgreSQL accepts connections from the entire `10.10.0.0/16` network.
- Finding 004: the Windows XP MRI workstation exposes multiple weaponized remote exploits without effective isolation.
- Finding 007: LDAP signing is not required on the primary Domain Controller.
- Finding 010: Alaris devices use default credentials and lack adequate isolation.
- Finding 016: Philips IntelliVue clinical interfaces are broadly reachable.
- Findings 001 and 002: the billing server contains a practical remote-execution-to-root attack chain.

These findings align directly with GAP-002, GAP-006, GAP-007, and the wider segmentation weaknesses identified in Project 1x00. Threat Scenario 1 demonstrates how weak identity controls, excessive internal reachability, vulnerable infrastructure, and insufficient backup isolation can be chained into enterprise ransomware.

**Risk Traceability:**  
**GAP-002 / GAP-006 / GAP-007 → Findings 003, 004, 007, 010 and 016 → Threat Scenario 1 and Kill Chains 1–4.**

### Key Gaps

The most significant Protect gap is **insufficient containment after initial compromise**.

MedDefense's flat architecture permits ordinary endpoints, Critical servers, Active Directory, recovery infrastructure, and clinical devices to remain unnecessarily close to one another. Identity protections are also incomplete because mandatory MFA is absent, legacy authentication weaknesses remain, and medical devices rely heavily on network trust.

This means successful compromise of one system can become an enterprise or patient-care incident instead of remaining confined to one security zone.

### Target Level: Managed

MedDefense should reach **Managed** maturity for Protect within six months.

The target should be demonstrated through documented and repeatable access controls, critical-system segmentation, stronger identity controls, controlled administrative access, formal vulnerability remediation, medical-device isolation, and secure configuration management.

The existing remediation roadmap already prioritizes the exposures that create the greatest attack-path value, including MRI segmentation, EHR database restrictions, LDAP protection, medical-device segmentation, and remediation of the Apache attack chain. The complete vulnerability program is estimated at:

**$54,000 immediate + $23,000 short-term + $19,000 medium-term + $65,000 long-term = $161,000.**

Because:

**$161,000 − $120,000 budget = $41,000 funding shortfall,**

not every proposed control can be implemented in the current funding cycle. Project 1x02 therefore commits **$116,000**, leaving:

**$120,000 − $116,000 = $4,000 contingency,**

and defers lower-priority work where interim controls exist.

A Managed target therefore requires disciplined prioritization rather than attempting to fund every control simultaneously.

---

# 4. DETECT (DE)

**Current Level: Not Implemented**

### Evidence

MedDefense generates logs, but generating logs is not equivalent to operating a detection capability.

The current environment relies substantially on local logging without centralized correlation, automated alerting, or continuous security monitoring. The Security Posture Assessment identifies the absence of effective internal monitoring as one of MedDefense's two most serious structural weaknesses.

**GAP-016 — No Centralized Security Monitoring or Log Correlation** states that successful compromises may remain undetected until an operational symptom occurs. The clearest evidence is `billing-srv-01`: unauthorized cryptomining operated for at least two weeks and was identified because of performance degradation rather than a security alert.

Threat Scenario 1 demonstrates how this deficiency affects an active attack. Reconnaissance, abnormal privileged authentication, EHR data extraction, backup destruction, and ransomware deployment can occur as separate events without the correlation needed to recognize the complete attack chain.

The vulnerability environment makes that detection deficiency particularly dangerous. For example, Finding 001 provides an exploitable billing-server entry point and Finding 004 provides multiple mature exploitation paths into the MRI environment. Without meaningful monitoring, exploitation of those weaknesses may not be discovered until business or clinical functionality is affected.

**Risk Traceability:**  
**GAP-016 → Finding 001 / Finding 004 → Threat Scenario 1.**

### Key Gaps

The central Detect gap is the absence of an operational **centralized detection and analysis capability**.

MedDefense does not currently demonstrate reliable correlation of firewall, Active Directory, server, endpoint, EHR, backup, and medical-device activity. It therefore lacks the ability to consistently distinguish routine activity from reconnaissance, credential abuse, lateral movement, data exfiltration, or destructive actions.

### Target Level: Managed

MedDefense should reach **Managed** maturity for Detect within six months.

At that level, logs from the highest-risk systems should be centrally collected and routinely reviewed, defined detection rules should exist for known MedDefense attack paths, alerts should have assigned owners and escalation procedures, and detection performance should be tested against the ransomware, identity, EHR, backup, and medical-device scenarios already developed in Project 1x01.

The objective is not to deploy monitoring because it is generally considered desirable. It is to detect the exact behaviors already modeled in MedDefense's threat scenarios: unusual VPN-originated enumeration, privileged account misuse, EHR bulk extraction, backup deletion, malicious Group Policy changes, and unexpected access to clinical-device interfaces.

---

# 5. RESPOND (RS)

**Current Level: Partial**

### Evidence

MedDefense has responded to previous incidents, so the Respond function is not completely absent. Historical events include ransomware, EHR downtime, website compromise, cryptomining on `billing-srv-01`, access-control failures, and other operational security events. Personnel have therefore performed containment, restoration, investigation, or troubleshooting activities when incidents became visible.

However, **GAP-012** states that MedDefense lacks a formal enterprise incident-response and recovery coordination process. The assessment does not establish a tested incident-response plan with clearly defined triage criteria, escalation paths, communications procedures, forensic responsibilities, breach-notification workflows, or recurring tabletop exercises.

This creates a material risk when the vulnerabilities documented in Project 1x02 are considered alongside the attack scenarios in Project 1x01. Findings 001 and 002, for example, create a practical path to root compromise of the billing server. Threat Scenario 1 then demonstrates how a foothold can progress into Active Directory compromise, PHI exfiltration, backup destruction, and enterprise ransomware. 

Without documented response procedures, MedDefense may contain one visible symptom without recognizing or eradicating the wider attack chain.

**Risk Traceability:**  
**GAP-012 → Findings 001 and 002 → Threat Scenario 1.**

### Key Gaps

The primary Respond gap is the lack of a **documented, tested, enterprise incident-management process**.

MedDefense must be able to determine who declares an incident, who can isolate clinical systems, who coordinates with Biomedical Engineering and vendors, when executives and legal/privacy personnel are notified, how evidence is preserved, how external parties are engaged, and how eradication is verified before systems return to operation.

### Target Level: Managed

MedDefense should achieve **Managed** Respond maturity within six months.

A Managed state should include a documented incident-response plan, severity and escalation criteria, named responsibilities, ransomware and PHI-breach playbooks, communications procedures, clinical-system containment procedures, forensic preservation requirements, and at least one documented exercise using a Project 1x01 scenario.

Managed is the appropriate target because the six-month goal is repeatability and readiness. Optimized maturity would require longer-term metrics, recurring exercises, lessons-learned integration, and measurable improvement over multiple response cycles.

---

# 6. RECOVER (RC)

**Current Level: Partial**

### Evidence

MedDefense has functioning recovery components. Veeam performs nightly backups of six Central virtual machines with 14-day retention, and a previous file-server restoration was successful. These facts demonstrate that recovery activity exists.

However, the recovery capability does not adequately cover MedDefense's Critical systems. **GAP-001** identifies no evidenced PACS recovery capability. **GAP-004** states that production and backup copies share the same network and physical failure domain. NAS-01 is located in the same server-room/rack environment as production and its management interface is broadly reachable. Only one partial file-server restoration has been tested, and the assessment reports no full disaster-recovery test.

Project 1x02 further identifies Finding 015: DSM management for the primary backup repository is reachable throughout the internal network and backups are stored unencrypted.

Threat Scenario 1 specifically includes the attacker reaching `backup-srv-01` and `NAS-01`, deleting or corrupting recovery points, and then deploying ransomware. This is the exact failure mode created by GAP-004: one compromised production environment can threaten both operational systems and their recovery mechanism.

**Risk Traceability:**  
**GAP-004 / GAP-001 → Finding 015 → Threat Scenario 1, Step 7.**

### Key Gaps

The primary Recover gap is the absence of **isolated, comprehensively tested recovery capability for Critical clinical and enterprise services**.

Backups currently exist, but the evidence does not demonstrate that MedDefense can reliably recover all Critical systems after ransomware, destructive compromise, or physical loss. PACS is a particularly significant gap, and the shared production/backup failure domain creates the possibility that the recovery system will fail during the same event it is intended to correct.

Defined and tested recovery-time objectives are also not evidenced.

### Target Level: Managed

MedDefense should reach **Managed** maturity for Recover within six months.

A Managed recovery capability should include isolated or immutable recovery copies for Critical systems, documented system recovery priorities, complete backup scope for identified Critical services, defined recovery objectives, protected backup administration, recurring restoration testing, and documented recovery communications.

The target directly addresses Threat Scenario 1. If ransomware reaches production, MedDefense must retain a recovery path that the attacker cannot destroy from the same compromised environment.

---

# Current Profile Summary

| NIST CSF Function | Current Level | Six-Month Target | Principal Evidence-Based Reason |
|---|---|---|---|
| **Govern** | **Partial** | **Managed** | Security activities exist, but enterprise strategy, formal risk governance, vulnerability governance, and response governance are incomplete. |
| **Identify** | **Partial** | **Managed** | The project established substantial asset/risk knowledge, but the organization historically lacked a reconciled, continuously maintained inventory and vulnerability-management process. |
| **Protect** | **Partial** | **Managed** | Existing safeguards are meaningful but inconsistent; Critical systems remain exposed by segmentation, identity, legacy-system, and configuration weaknesses. |
| **Detect** | **Not Implemented** | **Managed** | Logs exist, but there is no effective centralized monitoring, correlation, or alert-driven detection capability. |
| **Respond** | **Partial** | **Managed** | MedDefense has reacted to incidents but lacks a formal, tested enterprise incident-response process. |
| **Recover** | **Partial** | **Managed** | Backups exist, but coverage, isolation, testing, and Critical-system recovery remain incomplete. |

## Overall Assessment

MedDefense's NIST CSF profile is characterized by **isolated security activities without consistent enterprise integration**. Five of the six functions are Partial, while Detect is Not Implemented as an operational capability. The central six-month objective should therefore be to move from informal or assessment-driven activity to **documented, repeatable, organization-owned processes**.

The Target Profile does not require Optimized maturity within six months. That level would require sustained measurement and continuous improvement that MedDefense has not yet had time to demonstrate. Managed maturity is the appropriate objective because it establishes the repeatable governance, inventory, safeguards, detection, response, and recovery processes necessary to interrupt the specific attack paths already documented in Projects 1x00–1x02.
