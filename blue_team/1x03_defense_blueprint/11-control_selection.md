# MedDefense Health Systems  
## Task 11 — The Control Selection

### Framework Crosswalk Note

The MedDefense risk, cost, and expected-risk-reduction values below come from Tasks 6, 7, and 10. Exact CIS safeguard IDs are mapped to CIS Controls v8.1. NIST CSF mappings use the supplied NIST CSF 2.0 reference.

The same control can mitigate more than one risk. Therefore, costs and ALE reductions shown under multiple risks are **not additive portfolio values**. Repeating a control under several risks documents traceability; it does not mean MedDefense buys or counts the control more than once.

---

# RISK-001 — Enterprise Ransomware

## Control 1

Risk: RISK-001  
Selected Control: Network segmentation using enforceable VLANs, ACLs, and default-deny policy between user, server, EHR, Active Directory, backup, medical-device, guest, and management zones.  
CIS Control Mapping: CIS Control 12 — Network Infrastructure Management, Safeguard **12.2**; supporting CIS Control 13, Safeguard **13.4**.  
NIST CSF Mapping: **Protect.PR.IR — Technology Infrastructure Resilience**  
Control Type: Preventive  
Control Category: Technical  
Implementation Cost: **$10,000 infrastructure + (200 hours × $100/hour = $20,000) engineering + (100 hours × $50/hour = $5,000) maintenance = $35,000/year**  
Expected Risk Reduction: Enterprise ransomware ALE falls from **$2,864,400** to **$1,145,760**, so modeled reduction is **$2,864,400 − $1,145,760 = $1,718,640/year**.  
Dependencies: Requires the existing asset inventory and application/data-flow identification; no other Task 7 control must be deployed first. SIEM rules should be updated after segmentation so alerts understand approved cross-zone flows.

## Control 2

Risk: RISK-001  
Selected Control: MFA for VPN and all administrative accounts using the existing Microsoft 365 E3 identity capability.  
CIS Control Mapping: CIS Control 6 — Access Control Management, Safeguards **6.4** and **6.5**.  
NIST CSF Mapping: **Protect.PR.AA — Identity Management, Authentication, and Access Control**  
Control Type: Preventive  
Control Category: Technical  
Implementation Cost: **$0 incremental license + (80 hours × $75/hour = $6,000) implementation + (20 hours × $100/hour = $2,000) testing/training + (40 hours × $50/hour = $2,000) administration = $10,000/year**  
Expected Risk Reduction: Modeled enterprise ransomware ARO falls from **0.30** to **0.30 × (1 − 0.50) = 0.15**; ALE reduction is **$2,864,400 − $1,432,200 = $1,432,200/year**.  
Dependencies: Depends on the existing centralized identity/O365 environment; does not require segmentation or SIEM first.

## Control 3

Risk: RISK-001  
Selected Control: Wazuh SIEM with centralized collection, correlation, and alerting for FortiGate, Active Directory, EHR, servers, endpoints, backup infrastructure, and medical-device network events.  
CIS Control Mapping: CIS Control 8 — Audit Log Management, Safeguards **8.9** and **8.11**; supporting CIS Control 13, Safeguard **13.1**.  
NIST CSF Mapping: **Detect.DE.CM — Continuous Monitoring; Detect.DE.AE — Adverse Event Analysis**  
Control Type: Detective  
Control Category: Technical  
Implementation Cost: **$0 license + (160 hours × $75/hour = $12,000) deployment + (120 hours × $75/hour = $9,000) tuning/administration = $21,000/year**  
Expected Risk Reduction: Modeled enterprise incident EF falls from **100%** to **65%**; ALE reduction is **$2,864,400 − $1,861,860 = $1,002,540/year**.  
Dependencies: Requires log sources to be configured and time-synchronized. It does not require EDR first, but EDR and the Westside firewall provide higher-value telemetry once deployed.

## Control 4

Risk: RISK-001  
Selected Control: Sophos Intercept X / behavior-based EDR across conventional endpoints and servers.  
CIS Control Mapping: CIS Control 10 — Malware Defenses, Safeguard **10.7**; supporting CIS Control 13, Safeguard **13.7**.  
NIST CSF Mapping: **Protect.PR.PS — Platform Security; Detect.DE.CM — Continuous Monitoring**  
Control Type: Preventive  
Control Category: Technical  
Implementation Cost: **(515 endpoints × $30 = $15,450) + (14 servers × $100 = $1,400) + (82 hours × $75/hour = $6,150) deployment + $3,000 administration = $26,000/year**  
Expected Risk Reduction: Modeled ransomware ARO falls from **0.30** to **0.30 × (1 − 0.30) = 0.21**; ALE reduction is **$2,864,400 − $2,005,080 = $859,320/year**.  
Dependencies: Requires accurate endpoint/server inventory and centralized management. SIEM is not a prerequisite, but integrating EDR telemetry into SIEM improves correlation.

## Control 5

Risk: RISK-001  
Selected Control: Offsite immutable backup replication with isolated credentials and recurring restore tests.  
CIS Control Mapping: CIS Control 11 — Data Recovery, Safeguards **11.4** and **11.5**.  
NIST CSF Mapping: **Recover.RC.RP — Incident Recovery Plan Execution**  
Control Type: Corrective  
Control Category: Technical  
Implementation Cost: **$292 storage + $1,208 transfer/retrieval reserve + $3,000 integration + $3,500 testing/administration = $8,000/year**  
Expected Risk Reduction: Billing/recovery proxy ALE falls from **$135,143** to **$60,543**, so modeled reduction is **$135,143 − $60,543 = $74,600/year**. This is a recovery-specific benefit and must not be added independently to the full ransomware benefit without overlap adjustment.  
Dependencies: Depends on the existing backup process and repository; isolated credentials and successful restore testing are required before the control is considered effective.

---

# RISK-002 — EHR PHI Breach

## Control 1

Risk: RISK-002  
Selected Control: Network segmentation and database-path restriction so EHR database traffic is accepted only from approved EHR/application and administrative sources.  
CIS Control Mapping: CIS Control 12, Safeguard **12.2**; supporting CIS Control 13, Safeguard **13.4**.  
NIST CSF Mapping: **Protect.PR.IR**  
Control Type: Preventive  
Control Category: Technical  
Implementation Cost: The Task 7 enterprise segmentation program costs **$10,000 + $20,000 + $5,000 = $35,000/year**.  
Expected Risk Reduction: RISK-002's Task 6 direct database-control model reduces ALE from **$3,025,000** to **$1,210,000**, a reduction of **$3,025,000 − $1,210,000 = $1,815,000/year**. This risk-specific result is associated with restricting the EHR path; it is not added to the enterprise segmentation reduction as a separate portfolio benefit.  
Dependencies: Requires validated EHR application/database flow mapping before deny rules are enforced.

## Control 2

Risk: RISK-002  
Selected Control: MFA for privileged and remote EHR administration.  
CIS Control Mapping: CIS Control 6, Safeguards **6.4** and **6.5**.  
NIST CSF Mapping: **Protect.PR.AA**  
Control Type: Preventive  
Control Category: Technical  
Implementation Cost: **$0 + $6,000 + $2,000 + $2,000 = $10,000/year**  
Expected Risk Reduction: No separate EHR-only dollar amount was isolated in Task 7; the enterprise MFA model reduces ransomware ALE by **$2,864,400 − $1,432,200 = $1,432,200/year** across overlapping credential-driven risks.  
Dependencies: Existing centralized identity and compatible EHR administrative authentication.

## Control 3

Risk: RISK-002  
Selected Control: Wazuh SIEM alerts for abnormal EHR authentication, database connections, and bulk access/export behavior.  
CIS Control Mapping: CIS Control 8, Safeguards **8.9** and **8.11**; CIS Control 13, Safeguard **13.1**.  
NIST CSF Mapping: **Detect.DE.CM; Detect.DE.AE**  
Control Type: Detective  
Control Category: Technical  
Implementation Cost: **$0 + $12,000 + $9,000 = $21,000/year**  
Expected Risk Reduction: No independent EHR-only SIEM reduction was calculated. The enterprise SIEM model reduces ALE by **$2,864,400 − $1,861,860 = $1,002,540/year** across overlapping attack paths.  
Dependencies: Database, EHR, identity, and firewall logs must be onboarded before anomaly rules can operate.

---

# RISK-003 — Active Directory Compromise

## Control 1

Risk: RISK-003  
Selected Control: Mandatory MFA for VPN and administrative access, including privileged Active Directory administration.  
CIS Control Mapping: CIS Control 6, Safeguards **6.4** and **6.5**.  
NIST CSF Mapping: **Protect.PR.AA**  
Control Type: Preventive  
Control Category: Technical  
Implementation Cost: **$0 + $6,000 + $2,000 + $2,000 = $10,000/year**  
Expected Risk Reduction: The Task 7 enterprise credential-control model reduces ransomware ALE by **$2,864,400 − $1,432,200 = $1,432,200/year**. RISK-003 is an enabling stage inside that model, so a separate additive AD ALE is not claimed.  
Dependencies: Existing directory/identity services; administrative accounts must be identified before enforcement.

## Control 2

Risk: RISK-003  
Selected Control: Wazuh SIEM correlation for privileged group changes, unusual LDAP/Kerberos behavior, administrative authentication, and account creation.  
CIS Control Mapping: CIS Control 8, Safeguards **8.9** and **8.11**; CIS Control 13, Safeguard **13.1**.  
NIST CSF Mapping: **Detect.DE.CM; Detect.DE.AE**  
Control Type: Detective  
Control Category: Technical  
Implementation Cost: **$0 + $12,000 + $9,000 = $21,000/year**  
Expected Risk Reduction: Enterprise SIEM model reduction is **$2,864,400 − $1,861,860 = $1,002,540/year** across overlapping risks; no separate AD-only ALE is asserted.  
Dependencies: Domain Controller security-event and authentication logs must be forwarded to the SIEM.

---

# RISK-004 — Undetected Intrusion

## Control 1

Risk: RISK-004  
Selected Control: Wazuh SIEM with centralized security-event alerting and recurring audit-log review.  
CIS Control Mapping: CIS Control 8, Safeguards **8.9** and **8.11**; CIS Control 13, Safeguard **13.1**.  
NIST CSF Mapping: **Detect.DE.CM; Detect.DE.AE**  
Control Type: Detective  
Control Category: Technical  
Implementation Cost: **$0 + $12,000 + $9,000 = $21,000/year**  
Expected Risk Reduction: **$2,864,400 − $1,861,860 = $1,002,540/year** modeled enterprise reduction through earlier discovery/containment.  
Dependencies: Critical systems must generate and forward usable logs. Accurate time synchronization and log-source ownership are required.

## Control 2

Risk: RISK-004  
Selected Control: Sophos Intercept X / EDR to detect malicious processes, credential dumping, ransomware behavior, and suspicious endpoint/server activity.  
CIS Control Mapping: CIS Control 10, Safeguard **10.7**; CIS Control 13, Safeguard **13.7**.  
NIST CSF Mapping: **Detect.DE.CM; Protect.PR.PS**  
Control Type: Detective  
Control Category: Technical  
Implementation Cost: **$15,450 + $1,400 + $6,150 + $3,000 = $26,000/year**  
Expected Risk Reduction: **$2,864,400 − $2,005,080 = $859,320/year** modeled ransomware ALE reduction.  
Dependencies: Endpoint/server inventory and agent deployment. SIEM is not required for EDR to function, but SIEM should ingest EDR alerts.

---

# RISK-005 — Exploitation of Known Vulnerabilities

## Control 1

Risk: RISK-005  
Selected Control: EDR with behavior-based anti-malware and anti-exploitation capability on conventional endpoints and servers.  
CIS Control Mapping: CIS Control 10, Safeguard **10.7**; CIS Control 13, Safeguard **13.7**.  
NIST CSF Mapping: **Protect.PR.PS; Detect.DE.CM**  
Control Type: Preventive  
Control Category: Technical  
Implementation Cost: **$15,450 + $1,400 + $6,150 + $3,000 = $26,000/year**  
Expected Risk Reduction: The Task 7 model reduces ransomware ALE by **$2,864,400 − $2,005,080 = $859,320/year**. For the billing exploit subset, baseline ALE is **$473,000 ÷ 3.5 = $135,142.86 ≈ $135,143/year**, but Task 7 did not isolate the EDR-only share of that subset.  
Dependencies: Accurate managed-asset inventory and supported endpoint/server platforms.

## Control 2

Risk: RISK-005  
Selected Control: Network segmentation as a compensating control around unpatchable or legacy systems such as the MRI workstation.  
CIS Control Mapping: CIS Control 12, Safeguard **12.2**; CIS Control 13, Safeguard **13.4**.  
NIST CSF Mapping: **Protect.PR.IR**  
Control Type: Compensating  
Control Category: Technical  
Implementation Cost: **$10,000 + $20,000 + $5,000 = $35,000/year**  
Expected Risk Reduction: Enterprise segmentation reduction is **$2,864,400 − $1,145,760 = $1,718,640/year** across overlapping ransomware/lateral-movement risk. No separate legacy-system ALE is claimed.  
Dependencies: Asset ownership and allowed-flow mapping; vendor/clinical validation for systems that cannot be patched normally.

---

# RISK-006 — Insider PHI Exfiltration

## Control 1

Risk: RISK-006  
Selected Control: Wazuh SIEM monitoring for abnormal EHR exports, unusual access volume, removable-media-related endpoint events where available, and access outside expected working patterns.  
CIS Control Mapping: CIS Control 8, Safeguards **8.9** and **8.11**; CIS Control 13, Safeguard **13.1**.  
NIST CSF Mapping: **Detect.DE.CM; Detect.DE.AE**  
Control Type: Detective  
Control Category: Technical  
Implementation Cost: **$0 + $12,000 + $9,000 = $21,000/year**  
Expected Risk Reduction: No separate insider ALE reduction was calculated for SIEM. Current insider ALE remains **$120,000 × 2.5 = $300,000/year** until preventive USB/DLP controls are funded; SIEM improves detection but does not justify claiming the Task 6 DLP residual of $180,000.  
Dependencies: EHR audit, identity, endpoint, and data-access logs must be centralized.

## Control 2

Risk: RISK-006  
Selected Control: EDR on managed clinical endpoints to record and block suspicious execution and provide endpoint telemetry associated with removable-media or malware-assisted exfiltration.  
CIS Control Mapping: CIS Control 10, Safeguard **10.7**; CIS Control 13, Safeguard **13.7**.  
NIST CSF Mapping: **Detect.DE.CM; Protect.PR.PS**  
Control Type: Detective  
Control Category: Technical  
Implementation Cost: **$15,450 + $1,400 + $6,150 + $3,000 = $26,000/year**  
Expected Risk Reduction: No independent insider-exfiltration dollar reduction was established for EDR. The risk remains High in T10 because the funded T7 set does not contain preventive enterprise DLP/USB restriction.  
Dependencies: Endpoint inventory, agent coverage, and SIEM integration for centralized investigation.

---

# RISK-007 — Backup Destruction

## Control 1

Risk: RISK-007  
Selected Control: Offsite immutable backup replication with isolated credentials and recurring restore testing.  
CIS Control Mapping: CIS Control 11, Safeguards **11.4** and **11.5**.  
NIST CSF Mapping: **Recover.RC.RP**  
Control Type: Corrective  
Control Category: Technical  
Implementation Cost: **$292 + $1,208 + $3,000 + $3,500 = $8,000/year**  
Expected Risk Reduction: Recovery proxy ALE falls from **$135,143** to **$60,543**, giving **$135,143 − $60,543 = $74,600/year** modeled reduction.  
Dependencies: Existing backup jobs must be reliable first; recovery credentials must be separated from ordinary production administration.

## Control 2

Risk: RISK-007  
Selected Control: Network segmentation that isolates backup-management systems from ordinary production and user networks.  
CIS Control Mapping: CIS Control 12, Safeguard **12.2**; CIS Control 13, Safeguard **13.4**.  
NIST CSF Mapping: **Protect.PR.IR**  
Control Type: Preventive  
Control Category: Technical  
Implementation Cost: **$10,000 + $20,000 + $5,000 = $35,000/year**  
Expected Risk Reduction: No backup-only segmentation amount was isolated. Enterprise segmentation reduces modeled ransomware ALE by **$2,864,400 − $1,145,760 = $1,718,640/year** across overlapping attack paths.  
Dependencies: Backup communication flows and management hosts must be identified before default-deny rules are applied.

## Control 3

Risk: RISK-007  
Selected Control: SIEM alerts for backup-job deletion, retention changes, repository administrative login, and mass-deletion behavior.  
CIS Control Mapping: CIS Control 8, Safeguards **8.9** and **8.11**; CIS Control 13, Safeguard **13.1**.  
NIST CSF Mapping: **Detect.DE.CM; Detect.DE.AE**  
Control Type: Detective  
Control Category: Technical  
Implementation Cost: **$0 + $12,000 + $9,000 = $21,000/year**  
Expected Risk Reduction: No backup-specific SIEM dollar amount was isolated; the enterprise SIEM model provides **$2,864,400 − $1,861,860 = $1,002,540/year** of overlapping incident reduction.  
Dependencies: Backup server and repository administrative logs must be forwarded to SIEM.

---

# RISK-008 — Medical-Device Compromise

## Control 1

Risk: RISK-008  
Selected Control: Include medical-device networks in the funded enterprise segmentation program, with default-deny inter-zone filtering and only documented clinical/management flows allowed.  
CIS Control Mapping: CIS Control 12, Safeguard **12.2**; CIS Control 13, Safeguard **13.4**.  
NIST CSF Mapping: **Protect.PR.IR**  
Control Type: Preventive  
Control Category: Technical  
Implementation Cost: Medical-device segmentation is included in the **$10,000 + $20,000 + $5,000 = $35,000/year** enterprise segmentation program; the rejected dedicated medical-device architecture is not selected.  
Expected Risk Reduction: The targeted medical-device model reduces combined ALE from **$85,000** to **$25,500**, so modeled reduction is **$85,000 − $25,500 = $59,500/year** when segmentation is paired with credential remediation. The segmentation-only share was not isolated.  
Dependencies: Enterprise segmentation design must exist first; Biomedical Engineering and vendors must validate required device flows before enforcement.

## Control 2

Risk: RISK-008  
Selected Control: SIEM monitoring for abnormal medical-device traffic, cross-zone connection attempts, and management-interface access.  
CIS Control Mapping: CIS Control 8, Safeguards **8.9** and **8.11**; CIS Control 13, Safeguards **13.1** and **13.6**.  
NIST CSF Mapping: **Detect.DE.CM; Detect.DE.AE**  
Control Type: Detective  
Control Category: Technical  
Implementation Cost: **$0 + $12,000 + $9,000 = $21,000/year**  
Expected Risk Reduction: No separate medical-device SIEM ALE reduction was quantified. It supplements the targeted control model but is not credited with the full **$59,500/year** reduction by itself.  
Dependencies: Medical-device network segmentation and network-flow/log collection must be configured before device-specific alerts are reliable.

---

# RISK-009 — PACS/MRI Compromise

## Control 1

Risk: RISK-009  
Selected Control: Compensating isolation of the unsupported MRI workstation and PACS pathway using default-deny segmentation and allowlisted DICOM/vendor flows.  
CIS Control Mapping: CIS Control 12, Safeguard **12.2**; CIS Control 13, Safeguard **13.4**.  
NIST CSF Mapping: **Protect.PR.IR**  
Control Type: Compensating  
Control Category: Technical  
Implementation Cost: Included within the Task 7 enterprise segmentation cost of **$10,000 + $20,000 + $5,000 = $35,000/year**.  
Expected Risk Reduction: PACS/MRI ALE was not quantified in T10, so no dollar reduction is invented. The inherent score falls from **3 × 5 = 15** to residual **2 × 5 = 10** after isolation/monitoring in the T10 register.  
Dependencies: Requires verified PACS/MRI data flows, vendor access requirements, and clinical validation before ACL enforcement.

## Control 2

Risk: RISK-009  
Selected Control: Wazuh SIEM monitoring for MRI/PACS network anomalies, unauthorized RDP/SMB attempts, unexpected DICOM destinations, and vendor-access events.  
CIS Control Mapping: CIS Control 8, Safeguards **8.9** and **8.11**; CIS Control 13, Safeguard **13.1**.  
NIST CSF Mapping: **Detect.DE.CM; Detect.DE.AE**  
Control Type: Detective  
Control Category: Technical  
Implementation Cost: **$0 + $12,000 + $9,000 = $21,000/year**  
Expected Risk Reduction: No PACS/MRI ALE exists; this control supports the T10 residual-risk reduction from **15** to **10**, calculated as **3 × 5 = 15** before and **2 × 5 = 10** after.  
Dependencies: PACS, firewall, MRI-adjacent network, and vendor-access logs must be available.

---

# RISK-010 — Westside Trusted-Path Compromise

## Control 1

Risk: RISK-010  
Selected Control: Replace the consumer-grade Westside router with an enterprise-managed firewall supporting granular ACLs, secure administration, VPN policy, and centralized logging.  
CIS Control Mapping: CIS Control 12, Safeguard **12.2**; CIS Control 13, Safeguard **13.4**.  
NIST CSF Mapping: **Protect.PR.IR**  
Control Type: Preventive  
Control Category: Technical  
Implementation Cost: **$12,000 appliance/subscription + (50 hours × $100/hour = $5,000) migration + $3,000 support = $20,000/year**  
Expected Risk Reduction: Enterprise ransomware ARO falls from **0.30** to **0.30 × (1 − 0.05) = 0.285** for this alternate entry path; ALE reduction is **$2,864,400 − $2,721,180 = $143,220/year**.  
Dependencies: Should use the enterprise segmentation/ACL design so the Westside VPN receives only the minimum required Central access.

## Control 2

Risk: RISK-010  
Selected Control: Wazuh SIEM ingestion of Westside firewall/VPN events and alerts for unknown hosts, unusual VPN activity, and unauthorized Westside-to-Central traffic.  
CIS Control Mapping: CIS Control 8, Safeguards **8.9** and **8.11**; CIS Control 13, Safeguards **13.1** and **13.6**.  
NIST CSF Mapping: **Detect.DE.CM; Detect.DE.AE**  
Control Type: Detective  
Control Category: Technical  
Implementation Cost: **$0 + $12,000 + $9,000 = $21,000/year**  
Expected Risk Reduction: No separate Westside SIEM ALE amount was isolated; the enterprise SIEM model reduces overlapping ransomware ALE by **$2,864,400 − $1,861,860 = $1,002,540/year**.  
Dependencies: Enterprise firewall deployment or equivalent log-capable perimeter device must exist before full Westside telemetry can be centralized.

---

# Control Dependency Map

```text
FOUNDATIONAL STATE ALREADY COMPLETED
Asset Registry + Criticality + Data/Flow Knowledge
            |
            +------------------------------+
            |                              |
            v                              v
    MFA for VPN/Admin                Network Segmentation
       (no SIEM prerequisite)          CIS 12.2 / 13.4
            |                              |
            |                              +------------------------------+
            |                              |              |               |
            |                              v              v               v
            |                       EHR DB path      MRI/PACS        Medical-device
            |                       restriction      isolation        isolation
            |                                              \              /
            |                                               \            /
            |                                                v          v
            |                                            Clinical/vendor
            |                                            flow validation
            |
            +---------------------+
                                  |
                                  v
                         EDR Deployment
                         CIS 10.7 / 13.7
                                  |
                                  | telemetry
                                  v
LOG SOURCES ------------------> Wazuh SIEM
FortiGate / AD / EHR /        CIS 8.9 / 8.11 / 13.1
Servers / EDR / Backups /              |
Medical-device networks                |
                                       v
                              24/7 SOC / MDR
                              DEFERRED IN TASK 7
                              Requires SIEM + EDR first


EXISTING BACKUP JOBS
       |
       v
Offsite Immutable Backup
CIS 11.4 / 11.5
       |
       v
Restore Testing + Recovery Validation


ENTERPRISE SEGMENTATION DESIGN
       |
       v
Westside Enterprise Firewall
CIS 12.2 / 13.4
       |
       v
Westside SIEM/VPN Monitoring
```

## Dependency Interpretation

The principal sequencing rule is that **architecture comes before specialized isolation**. The enterprise segmentation design establishes zones and allowed traffic; EHR, MRI/PACS, and medical-device isolation are then implemented inside that architecture. The Westside firewall should inherit the same least-privilege network design rather than create a separate trust model.

**SIEM does not technically require EDR**, but the SIEM becomes more effective after EDR, firewall, identity, EHR, backup, and network telemetry are available. The deferred 24/7 SOC is different: it should follow SIEM and EDR because a managed SOC without mature telemetry would be paying analysts to monitor incomplete evidence.

**Immutable recovery can proceed in parallel** with segmentation, MFA, EDR, and SIEM because its dependency is the existing backup process, not another security product. Recovery is only considered effective after a successful restore test.

---

# Control Selection Summary

| Risk | Selected Controls | Primary CIS Safeguards | Primary NIST CSF |
|---|---|---|---|
| RISK-001 | Segmentation, MFA, SIEM, EDR, immutable backup | 12.2, 13.4, 6.4, 6.5, 8.9, 8.11, 13.1, 10.7, 13.7, 11.4, 11.5 | PR.IR, PR.AA, DE.CM, DE.AE, PR.PS, RC.RP |
| RISK-002 | Segmentation, MFA, SIEM | 12.2, 13.4, 6.4, 6.5, 8.9, 8.11, 13.1 | PR.IR, PR.AA, DE.CM, DE.AE |
| RISK-003 | MFA, SIEM | 6.4, 6.5, 8.9, 8.11, 13.1 | PR.AA, DE.CM, DE.AE |
| RISK-004 | SIEM, EDR | 8.9, 8.11, 13.1, 10.7, 13.7 | DE.CM, DE.AE, PR.PS |
| RISK-005 | EDR, segmentation | 10.7, 13.7, 12.2, 13.4 | PR.PS, DE.CM, PR.IR |
| RISK-006 | SIEM, EDR | 8.9, 8.11, 13.1, 10.7, 13.7 | DE.CM, DE.AE, PR.PS |
| RISK-007 | Immutable backup, segmentation, SIEM | 11.4, 11.5, 12.2, 13.4, 8.9, 8.11, 13.1 | RC.RP, PR.IR, DE.CM, DE.AE |
| RISK-008 | Segmentation, SIEM | 12.2, 13.4, 8.9, 8.11, 13.1, 13.6 | PR.IR, DE.CM, DE.AE |
| RISK-009 | Segmentation, SIEM | 12.2, 13.4, 8.9, 8.11, 13.1 | PR.IR, DE.CM, DE.AE |
| RISK-010 | Westside firewall, SIEM | 12.2, 13.4, 8.9, 8.11, 13.1, 13.6 | PR.IR, DE.CM, DE.AE |

### Budget Consistency

The unique funded Task 7 controls used by this selection are:

- Network segmentation: **$35,000**
- MFA: **$10,000**
- Wazuh SIEM: **$21,000**
- EDR: **$26,000**
- Westside firewall: **$20,000**
- Immutable backup: **$8,000**

Total unique control spend:

**$35,000 + $10,000 + $21,000 + $26,000 + $20,000 + $8,000 = $120,000**

Budget:

**$120,000**

Remaining:

**$120,000 − $120,000 = $0**

Therefore, the control set is traceable to the ten mitigated risks and remains within the binding Task 7/8 budget because **$120,000 = $120,000**. Repeated mappings in this document do not create additional cost.
