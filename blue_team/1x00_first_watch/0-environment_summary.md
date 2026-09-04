# MedDefense Health Systems — Structured Environment Summary

**Prepared by:** Security Analyst (Office of the Deputy CISO)
**Prepared for:** James Chen, Deputy CISO
**Source:** MedDefense onboarding packet (HR guide, IT asset export, Marcus Webb's notes, contracts summary, draft network diagram, org chart)

---

## 1. Organization Overview

### 1.1 Sites

| Site | Location Type | Function | Staff | Facility |
|---|---|---|---|---|
| MedDefense Central Hospital | Downtown, urban | 350-bed acute care hospital | ~1,400 | 6 floors + basement server room; underground staff garage, surface visitor lot |
| Westside Clinic | Suburban, 12 min from Central | Outpatient: primary care, imaging (X-ray, ultrasound, no MRI), blood work, minor procedures, PT | ~180 | 2-story medical office; shared retail plaza parking; own local server closet |
| Corporate HQ | Greenfield Business Park, 15 min from Central | Admin/executive functions | ~220 | Leased space, 3rd floor of 5-story building; no on-prem servers |
| **Stated org-wide total** | — | — | **~2,000** | Sum of sites above = ~1,800 (see Known Unknowns) |

### 1.2 Departments by Site

| Site | Departments |
|---|---|
| Central | Emergency, Surgery, Cardiology, Radiology, Oncology, Pediatrics, Maternity, Pharmacy, Laboratory, Administration |
| Westside | Primary care, diagnostic imaging, blood work, minor procedures, physical therapy |
| HQ | Finance, HR, Legal, Marketing, Executive Leadership, IT (12 staff) |

### 1.3 Reporting Structure (Security-Relevant)

| Role | Reports To | Notes |
|---|---|---|
| CEO — Dr. Patricia Morales | — | Top of org chart |
| CFO — Robert Kim | CEO | — |
| COO — Angela Torres | CEO | Clinical Directors report to COO |
| General Counsel — David Park | CEO | Claims HIPAA compliance, no evidence cited |
| CISO | CEO | **Vacant** |
| Deputy CISO — James Chen | Vacant CISO role | De facto reports to CEO; has security policy authority, no IT operations authority |
| Security Analyst (this role) | James Chen | Replacing Marcus Webb |
| IT Director — Sarah Park | Vacant CISO role | Peer of James Chen, not subordinate |
| IT team (Sarah Park's org) | Sarah Park | 3 Sys Admins, 2 Network Techs, 1 DBA, 2 Helpdesk Analysts, 2 Desktop Support, 1 vacant IT Intern |

**Governance flag:** James Chen sets security policy but has no authority over Sarah Park's team, which controls the infrastructure. Org chart explicitly notes this creates friction.

---

## 2. IT Infrastructure Identified

### 2.1 Servers — Central

| Host | OS/Platform | Function | Notes |
|---|---|---|---|
| ehr-srv-01 | Ubuntu 20.04 LTS | EHR application server | SSH key-only migration started, only host completed |
| ehr-db-01 | Ubuntu 20.04 LTS | EHR database (PostgreSQL) | Reachable from entire 10.10.0.0/16, not restricted to ehr-srv-01 |
| pacs-srv-01 | Windows Server 2016 | PACS imaging server | Radiology uses shared login ("raduser") |
| billing-srv-01 | Ubuntu 18.04 LTS | Billing/claims processing | Recurring unexplained performance issues; target of January ransomware incident |
| ad-dc-01 / ad-dc-02 | Windows Server 2019 | Primary/secondary domain controllers | Core auth infrastructure |
| file-srv-01 | Windows Server 2016 | Department file shares | — |
| print-srv-01 | Windows Server 2012 R2 | Print server | [UNVERIFIED] in ticketing system; OS end-of-support Oct 2023 |
| backup-srv-01 | Ubuntu 22.04 LTS | Backup server (Veeam agent) | Backs up to NAS in same room/network/rack as production; offsite backup budget denied |
| web-srv-01 | Ubuntu 20.04 LTS | Public website + patient portal | Sits in DMZ per network diagram |

### 2.2 Servers — Westside / HQ

| Host | OS/Platform | Function | Notes |
|---|---|---|---|
| ws-srv-01 | Windows Server 2016 | Local file server + scheduling | Westside |
| Unconfirmed 2nd server | Unknown | Unknown | Possible server in Westside closet, mentioned by Mike Torres, never verified |
| (none) | — | — | HQ has no on-prem servers; uses cloud services + site-to-site VPN to Central |

### 2.3 Network Equipment

| Site | Equipment |
|---|---|
| Central | Cisco core switch (model unrecorded), 2x Cisco access switches/floor, 1x FortiGate 100F (also VPN termination for all sites), 12x Ubiquiti UniFi APs |
| Westside | 1x unmanaged switch (brand unknown), 1x consumer router (Netgear Nighthawk); **no firewall**; site-to-site VPN runs over this consumer router |
| HQ | Landlord-managed network; MedDefense has own VLAN |

**Topology:** Central is a single flat network (10.10.0.0/16), no VLAN segmentation. Workstations, servers, and medical devices share one broadcast domain. Segmentation "planned for next fiscal year" per Sarah Park, as of 4+ months ago. Guest WiFi SSID exists at Central; isolation unverified.

### 2.4 Endpoints

| Site | Endpoints | Age of Data |
|---|---|---|
| Central | ~320 Windows 10 workstations, ~60 thin clients (clinical) | AD report, 8 months old |
| Westside | ~45 Windows 10 workstations | Same report |
| HQ | ~120 Windows 10/11 workstations, ~30 remote-capable laptops | Same report |
| Org-wide | ~25 physician iPads (rounds); MDM enrollment status unclear | — |

No current, complete endpoint count exists per Marcus's notes.

### 2.5 Medical Devices (IoT)

| Device | Count/Model | Location | Risk Note |
|---|---|---|---|
| Patient monitors | ~80, Philips IntelliVue | Central | On flat, unsegmented network |
| Infusion pumps | ~120, BD Alaris | Central | Network-connected for dosage updates; reachable if network is breached |
| MRI scanner | 1x Siemens MAGNETOM | Radiology, Central | Runs Windows XP — flagged CRITICAL by Marcus |
| CT scanner | 1x GE Revolution | Central | OS unrecorded |
| Nurse call system | IP-based | Central | Integrated with phone system |
| Badge/access (HID Global) | Org-wide (partial) | All sites | AD-integrated for "some doors" only; scope undefined |

### 2.6 Authentication and Access

| Control | Status |
|---|---|
| Password policy | 8-char minimum, 90-day rotation, complexity enabled |
| MFA | None org-wide except James Chen's personal account (self-configured) |
| SSH auth (Linux servers) | Password-based on all hosts except ehr-srv-01 (key-only, partial migration) |
| PACS login | Shared credential ("raduser") used by Radiology department |

---

## 3. Data and Services

### 3.1 Data Types Handled

| Data Type | Source System(s) |
|---|---|
| Protected Health Information (PHI) | EHR (ehr-srv-01/db-01), PACS, medical devices, patient portal |
| Billing/claims/financial data | billing-srv-01 |
| Employee data (HR/payroll) | HR/Finance functions at HQ; no specific system named |
| Authentication data | Active Directory (ad-dc-01/02) |

### 3.2 Critical Services and Dependencies

| Service | Depends On | Primary Users | Impact if Disrupted |
|---|---|---|---|
| EHR | ehr-srv-01, ehr-db-01 | Clinical staff, Central + Westside | Patient care documentation halted |
| PACS (imaging) | pacs-srv-01 | Radiology (Central); Westside imaging via network | Diagnostic imaging access lost |
| Billing/claims | billing-srv-01 | Administration/Finance | Revenue cycle disrupted; already targeted (Jan. ransomware) |
| Patient portal | web-srv-01 (DMZ) | Patients | Public-facing outage |
| Medical device network | Flat 10.10.0.0/16 | Clinical staff, patients (monitors/pumps) | Life-safety risk, not just operational |
| Nurse call | IP-based, integrated w/ phone system | Central clinical staff | Safety communication impaired |
| Badge/access control | HID Global + AD (partial) | Org-wide | Physical access control impaired |
| Site-to-site VPN | Single FortiGate 100F | Westside, HQ | Both sites lose access to shared services on single point of failure |

### 3.3 User Groups

| User Group | Size | Systems Used |
|---|---|---|
| Clinical staff, Central | ~1,400 | EHR, PACS, medical devices, nurse call |
| Clinical/admin staff, Westside | ~180 | EHR (shared services), local file/scheduling, imaging |
| Admin/corporate staff, HQ | ~220 | Billing/claims, O365, VPN to Central |
| Physicians | Subset of clinical staff | iPads, EHR, PACS |
| Patients | External | Website, patient portal |
| IT/Security staff | 13 (12 IT + Security Analyst) | Direct admin access to servers, network, AD |

### 3.4 IT Service Contracts and Costs

| Vendor | Service | Annual Cost | Renewal | Notes |
|---|---|---|---|---|
| Microsoft | O365 E3, org-wide | $432,000 | September | Largest line item; no MFA deployed despite this spend |
| MedTech Solutions | EHR maintenance | $145,000 | July | Software updates only, not hardware; SLA 4hr critical / 24hr standard; access scope undocumented |
| ClearView Security | Guard service, Central only | $96,000 | December | 1 guard, Mon–Fri 7AM–7PM; no coverage nights/weekends/Westside/HQ; none near server room |
| Sophos | Endpoint protection | $18,000 | January | Org-wide; current status on all machines unverified |
| Veeam | Backup software | $8,500 | March | Licenses backup-srv-01; backups stored with production data (see 2.1) |
| Fortinet | FortiGate support | $4,200 | June | Supports the single firewall/VPN termination point for all sites |
| Ubiquiti | UniFi controller license | $0 (free) | N/A | Manages 12 Central APs |
| Greenfield Bldg Mgmt | HQ network/internet | Included in lease | N/A | No standalone cost |
| **Total documented spend** | | **~$703,700** | | Excludes lease-included HQ network item |

---

## 4. Known Unknowns

| # | Gap/Contradiction | Detail |
|---|---|---|
| 1 | Headcount mismatch | Stated org total ~2,000; sites sum to ~1,800. ~200 unaccounted for. |
| 2 | Unconfirmed Westside server | Possible 2nd server in closet, mentioned by Mike Torres, never verified; not on asset list. |
| 3 | Stale/unverified assets | print-srv-01 [UNVERIFIED] >1 year; endpoint counts based on 8-month-old AD report; core switch model unrecorded; Westside switch brand unrecorded; Westside WiFi equipment undocumented. |
| 4 | Ambiguous device management | iPad MDM enrollment status unclear; HID/AD door integration scope ("some doors") undefined; CT scanner OS unrecorded. |
| 5 | Unverified controls | Guest WiFi isolation at Central unverified; HQ VPN ACLs unaudited; Sophos AV currency unverified across fleet. |
| 6 | Unexplained technical issue | billing-srv-01 performance issues unresolved, root cause undocumented; relation to Jan. ransomware unclear. |
| 7 | Incomplete cloud inventory | O365 confirmed; other department-level cloud services suspected, not inventoried (shadow IT risk). |
| 8 | No completed assessments | No formal HIPAA Security Rule assessment (Legal claims compliance, no evidence); no vulnerability assessment; no endpoint security evaluation; no threat landscape analysis. |
| 9 | No IR/BC/DR plans | January ransomware response was ad hoc (4 days, improvised); no documented incident response, business continuity, or disaster recovery plan; UPS runtime ~20 min with no follow-on procedure. |
| 10 | Physical security gaps | Server room uses generic all-staff badge (flagged 5 months ago, "on roadmap"); no cameras in server room corridor; Westside closet doesn't lock. |
| 11 | Vendor access undocumented | MedTech, ClearView, and Sophos contracts define service and cost, not the technical/physical access each vendor holds. |
| 12 | Governance ambiguity | CISO role vacant; James Chen has policy authority, no IT operations authority; effect on remediation timelines undocumented. |
| 13 | Diagram incomplete | Marcus's network diagram explicitly labeled a simplified draft; real topology stated to be "messier." |
