# MedDefense Health Systems
## Task 14 — The Segmentation Architecture

### Design Objective

MedDefense currently uses different IP ranges for workstations, servers, and medical devices, but those ranges are not enforced as security boundaries. The new design converts those ranges into routed VLANs with firewall policy between them and adds dedicated Management, Backup/Recovery, and DMZ zones.

The required five zones plus two additional high-value zones produce:

**5 required zones + 2 additional zones = 7 security zones**

The architectural rule is:

**Default deny between zones; explicitly allow only documented business and clinical flows.**

A site-to-site VPN or compromised internal host must never inherit broad `10.10.0.0/16` reachability.

# Part 1 — Zone Definition

| Zone | IP Range | Purpose / Systems Included | Allowed Outbound Connections | Allowed Inbound Connections |
|---|---|---|---|---|
| **VLAN 10 — Clinical Workstations** | **10.10.1.0/24** | Nurse stations, physician workstations, reception/clinical endpoints, managed Radiology user workstations. The MRI workstation is moved out of this zone. | EHR application; AD/DNS/Kerberos; authorized PACS/DICOM; secured Internet egress. No direct database, backup-management, or medical-device-management access. | Management-zone administration/security tooling only. No inbound initiation from Guest or Medical Device zones. |
| **VLAN 20 — Server Zone** | **10.10.2.0/24** | `ehr-srv-01`, `ehr-db-01`, `billing-srv-01`, file/print servers, `ad-dc-01`, `ad-dc-02`, and approved internal applications. | Required application dependencies, AD/DNS, Backup Zone, updates, SIEM forwarding. | Published application access from Clinical; administrative access from Management; backup traffic from Backup Zone. |
| **VLAN 30 — Medical Device / Imaging Zone** | **10.10.3.0/24** | Philips IntelliVue monitors, BD Alaris pumps, `WS-RAD-01`, PACS, nurse-call endpoints, and clinical IoT. | Approved DICOM, HL7, vendor/update, and monitoring flows only. | Authorized clinical systems, approved EHR/interface systems, Management Zone, and controlled vendor support only. |
| **VLAN 40 — Management Zone** | **10.10.4.0/24** | IT administrative workstations, jump host, vulnerability scanner, Wazuh/SIEM management systems, network-management interfaces. | Administrative protocols to managed systems and approved security-management traffic. | Only approved administrator identities using MFA from managed administration devices. |
| **VLAN 50 — Guest / Non-Clinical IoT** | **10.10.5.0/24** | Visitor Wi-Fi and non-clinical consumer/IoT devices. | Internet DNS/HTTP/HTTPS only. | Return traffic from established Internet sessions and explicitly approved Management access. |
| **VLAN 60 — Backup / Recovery Zone** | **10.10.6.0/24** | `backup-srv-01`, `NAS-01`, recovery-management systems, immutable/offsite replication gateways. | Backup replication, recovery operations, SIEM logging, immutable-storage connections. | Approved server backup traffic and Management Zone administration only. |
| **VLAN 70 — DMZ / Public Services** | **10.10.7.0/24** | Patient portal, public web services, reverse proxy, and other Internet-facing services. | Explicit internal application dependencies, DNS/NTP/updates, SIEM logging. | Internet access only to published services such as HTTPS. |

The existing Central ranges are deliberately retained where practical: `10.10.1.0/24` remains the workstation range, `10.10.2.0/24` remains the server range, and `10.10.3.0/24` becomes an enforced medical-device boundary rather than merely an addressing convention. The asset registry currently places `pacs-srv-01` at `10.10.2.12` and `WS-RAD-01` at `10.10.1.70`; both should be migrated into the Medical/Imaging security boundary because PACS and MRI are part of the same high-risk clinical workflow.

Westside and HQ should also lose broad site-to-site trust. VPN traffic should terminate at the firewall and be subjected to the same least-privilege zone policy rather than receiving access to the entire Central environment.

# Part 2 — Critical Firewall Rules

The rules are processed from top to bottom. Traffic that does not match an approved allow rule is denied.

| # | Firewall Rule | Action | Purpose |
|---:|---|---|---|
| **1** | `Clinical_Workstations -> EHR_App : TCP/443, TCP/8080 : ALLOW` | Allow | Permits normal clinician access without exposing the EHR database directly. |
| **2** | `EHR_App_Server -> EHR_DB : TCP/5432 : ALLOW` | Allow | Makes the EHR application server the approved PostgreSQL path and removes the current `/16` database exposure. |
| **3** | `Clinical_Workstations -> Active_Directory : UDP/TCP 53, UDP/TCP 88, TCP 389/636, TCP 445 : ALLOW` | Allow | Preserves DNS, Kerberos, LDAP/LDAPS, and domain-policy functionality while keeping administrative access elsewhere. |
| **4** | `Authorized_Radiology_Workstations + MRI -> PACS : TCP/4242, TCP/11112 : ALLOW` | Allow | Preserves DICOM imaging workflows while preventing unrelated endpoints from reaching PACS. |
| **5** | `Philips_Monitors -> Approved_HL7_Interface : TCP/2575 : ALLOW` | Allow | Allows required HL7 exchange only to the approved destination. |
| **6** | `Management_Zone -> Managed_Systems : TCP/22, TCP/443, TCP/3389, TCP/5985-5986 : ALLOW` | Allow | Restricts administrative protocols to controlled admin workstations and jump systems. |
| **7** | `Backup_Zone -> Approved_Servers : TCP/22, TCP/443, TCP/445 : ALLOW` | Allow | Permits approved backup/restore communication while keeping recovery infrastructure isolated. |
| **8** | `Guest_IoT -> Internet : UDP/TCP 53 to approved resolver; TCP/80,443 : ALLOW` | Allow | Provides visitor/non-clinical Internet access without access to clinical systems. |
| **9** | `Clinical + Medical + Guest_IoT + Server -> Management_Zone or Backup_Admin : ANY : DENY` | **Deny** | Prevents a compromised workstation, device, application server, or guest asset from reaching security administration or backup management. |
| **10** | `ANY_ZONE -> ANY_OTHER_ZONE : ANY not explicitly allowed : DENY` | **Deny** | Blocks undocumented east-west movement and establishes default-deny segmentation. |

### Deny-Rule Impact

**Rule 9** protects the two highest-value control planes: administration and recovery. Under the current flat architecture, compromised hosts can attempt to reach administrative systems and backup interfaces. This rule prevents that direct path.

**Rule 10** is the fundamental architectural change. A system no longer becomes trusted simply because it is “inside.” A new shadow system, compromised workstation, medical device, or VPN foothold receives no cross-zone access unless a documented rule explicitly permits it.

# Part 3 — Kill Chain Impact

## Kill Chain #1 — FortiGate VPN Exploitation to EHR Database Compromise

The 1x01 chain is:

**FortiGate VPN exploitation → internal foothold → lateral movement to EHR → EHR objective execution → clinical/financial/regulatory impact.**

### Step 1 — Initial Access

**Segmentation does not break this step.**

An exploitable Internet-facing FortiGate can still be compromised. The relevant controls are perimeter vulnerability management, patching, configuration hardening, and attack-surface reduction.

The segmentation design is not credited with preventing something it cannot prevent.

### Step 2 — Establish Foothold

**Segmentation partially disrupts this step.**

Today, compromise of the VPN gateway gives the attacker proximity to broadly reachable internal systems.

Under the proposed architecture, VPN-originated traffic is subject to inter-zone policy and can reach only approved services. Control of the VPN therefore no longer automatically means control of an unrestricted `10.10.0.0/16` network.

### Step 3 — Lateral Movement to EHR

**This is the primary break point.**

The original attack depends on directly reaching:

`ehr-db-01:5432`

Finding 003 confirms that the current PostgreSQL configuration accepts connections from the wider internal network.

The proposed architecture instead permits:

`EHR_App_Server -> EHR_DB : TCP/5432 : ALLOW`

while Rule 10 denies every undocumented path.

Therefore:

`VPN_or_other_foothold -> EHR_DB : TCP/5432 : DENY`

The attacker must now compromise an explicitly trusted application system before reaching the PHI database.

### Step 4 — Objective Execution

**Segmentation supplies a second containment layer.**

Even if `ehr-srv-01` is compromised, it does not gain unrestricted access to:

- Backup administration.
- Medical-device administration.
- Management workstations.
- Guest/IoT systems.
- Unrelated server services.

The EHR incident remains serious, but it becomes less capable of expanding into an enterprise-wide event.

### Step 5 — Impact

**Segmentation reduces blast radius; it does not eliminate the EHR risk.**

If the attacker successfully compromises the EHR application and database through an approved path, confidentiality, integrity, and availability remain at risk.

The architectural change is therefore:

**Current state:** perimeter compromise → broad enterprise reachability

**Target state:** perimeter compromise → small set of explicitly permitted services

# Impact Across the Top Five Kill Chains

The cross-chain analysis identifies segmentation as a recurring defensive break point for Kill Chains 1 through 4. Kill Chain 5 differs because the malicious actor already possesses legitimate network-core administrative authority.

| Kill Chain | Segmentation Impact | Break Point |
|---|---|---|
| **KC-1 — VPN → EHR** | **Disrupted** | Step 3: VPN foothold cannot directly reach PostgreSQL. |
| **KC-2 — Phishing → Active Directory** | **Disrupted** | Step 3: compromised ordinary endpoints cannot use privileged management paths; administration is restricted to the Management Zone. |
| **KC-3 — Supply Chain → PACS/MRI** | **Disrupted** | Step 3: compromised imaging assets are confined to approved DICOM/vendor flows. |
| **KC-4 — Phishing → Backup Destruction** | **Disrupted** | Step 3: compromised endpoints cannot directly administer backup systems. |
| **KC-5 — Malicious Insider → Network Core** | **Not reliably disrupted by segmentation alone** | The insider already controls network infrastructure and may be able to change the firewall/VLAN policy itself. PAM, MFA, separation of duties, configuration monitoring, and two-person change approval are required. |

Segmentation therefore materially disrupts:

**4 kill chains ÷ 5 top kill chains × 100 = 80%**

of the top five modeled kill chains.

The **80%** figure means the documented attack route is broken or materially constrained. It does not mean four threats disappear entirely.
