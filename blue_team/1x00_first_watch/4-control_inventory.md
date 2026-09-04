# MedDefense Health Systems
## The Control Landscape: Existing Security Controls Inventory

---

## 1. Control Inventory

Sixteen distinct controls were identified across all three categories. Each entry states what the control does, why it is classified as it is, and the specific asset or zone it protects.

```
Control ID: C-001
Control Name: Default-Deny Firewall Policy
Description: The FortiGate 100F firewall's final policy rule ("Deny-All", rule 5) denies all traffic that does not match a preceding explicit allow rule, with full logging enabled. This enforces a whitelist model in which only traffic explicitly permitted by rules 1-4 can traverse the firewall, rather than a default-allow posture.
Category: Technical
Function: Preventive
Asset(s) Protected: Internal network and server subnet (all zones behind the firewall)
Source: Artifact 1 - Firewall Configuration Extract, rule 5
```

```
Control ID: C-002
Control Name: Web Server Inbound Service Restriction
Description: Rule 1 ("Allow-Web-Inbound") restricts inbound traffic from the WAN to web-srv-01 to only the HTTP and HTTPS services. This limits the exposed attack surface of the only server intentionally reachable from the public internet to two well-defined, expected protocols, rather than opening all ports.
Category: Technical
Function: Preventive
Asset(s) Protected: web-srv-01 (public-facing web/portal server)
Source: Artifact 1 - Firewall Configuration Extract, rule 1
```

```
Control ID: C-003
Control Name: VPN Source-Subnet Restriction
Description: Rules 2 and 3 ("Allow-VPN-Westside" and "Allow-VPN-HQ") restrict which source subnets (westside-subnet, hq-subnet) may reach the server subnet over VPN, rather than accepting VPN traffic from any source. Although the service scope for these rules is unrestricted ("ALL", a documented weakness), the source/destination restriction itself is a real control that prevents VPN traffic from unrecognized networks from reaching internal servers.
Category: Technical
Function: Preventive
Asset(s) Protected: Server subnet (internal zone), reachable via Westside and HQ VPN tunnels
Source: Artifact 1 - Firewall Configuration Extract, rules 2-3
```

```
Control ID: C-004
Control Name: Firewall Traffic Logging
Description: Every firewall policy rule has logging enabled ("logtraffic all" on the inbound and deny rules, "logtraffic utm" on the VPN and outbound rules), meaning traffic that is permitted, denied, or inspected is recorded locally on the FortiGate. This provides a record that can be reviewed after a suspected incident to establish what traffic crossed the perimeter, even though the logs are not currently forwarded or centrally retained (see Artifact 8).
Category: Technical
Function: Detective
Asset(s) Protected: DMZ, VPN ingress points, internal-to-WAN egress, and all denied traffic
Source: Artifact 1 - Firewall Configuration Extract, all rules
```

```
Control ID: C-005
Control Name: SSH Public-Key-Only Authentication (ehr-srv-01)
Description: On ehr-srv-01, PasswordAuthentication is set to "no" and PubkeyAuthentication is set to "yes", meaning remote administrative login requires possession of a private key rather than a guessable or phishable password. Root login is also disabled (PermitRootLogin no), forcing authentication as a named account before privilege escalation. This directly protects the server holding the EHR application, which stores protected health information.
Category: Technical
Function: Preventive
Asset(s) Protected: ehr-srv-01 (EHR application server)
Source: Artifact 2 - SSH Configuration, sshd_config
```

```
Control ID: C-006
Control Name: SSH Brute-Force and Idle-Session Controls
Description: MaxAuthTries is capped at 3 and LoginGraceTime at 60 seconds, limiting the number of authentication attempts an attacker can make per connection and how long an unauthenticated session may remain open. ClientAliveInterval (300) and ClientAliveCountMax (2) terminate idle authenticated sessions after approximately 10 minutes of inactivity, reducing the window in which an unattended, unlocked session could be hijacked.
Category: Technical
Function: Preventive
Asset(s) Protected: ehr-srv-01 (EHR application server)
Source: Artifact 2 - SSH Configuration, sshd_config
```

```
Control ID: C-007
Control Name: SSH Authentication Logging
Description: SyslogFacility is set to AUTH and LogLevel to VERBOSE, so every authentication attempt (successful or failed) against ehr-srv-01 is recorded in detail. This creates the evidentiary basis needed to identify brute-force attempts or unauthorized access after the fact, even though these logs are not currently forwarded to a central system (see Artifact 8).
Category: Technical
Function: Detective
Asset(s) Protected: ehr-srv-01 (EHR application server)
Source: Artifact 2 - SSH Configuration, sshd_config
```

```
Control ID: C-008
Control Name: SSH Forwarding Disabled
Description: X11Forwarding and AllowTcpForwarding are both set to "no" on ehr-srv-01. This prevents an authenticated SSH session from being used as a tunnel to reach other internal hosts or to forward graphical sessions, reducing the ways a compromised or legitimate SSH credential could be repurposed to pivot further into the network.
Category: Technical
Function: Preventive
Asset(s) Protected: ehr-srv-01 (EHR application server) and adjacent internal hosts reachable via tunneling
Source: Artifact 2 - SSH Configuration, sshd_config
```

```
Control ID: C-009
Control Name: Password Complexity, Rotation and History Policy
Description: The documented Information Security Policy requires a minimum 8-character password with uppercase, lowercase, numeric and special-character complexity, mandates rotation every 90 days, and retains a history of the last 5 passwords to prevent immediate reuse. This is a formal, approved administrative control that sets the baseline credential strength expected of every employee, contractor and vendor account.
Category: Administrative
Function: Preventive
Asset(s) Protected: All user accounts across MedDefense information systems
Source: Artifact 3 - Password Policy document, section 2
```

```
Control ID: C-010
Control Name: Account Lockout Policy
Description: The password policy specifies that accounts lock for 30 minutes after 5 failed login attempts, and this is enforced technically through Active Directory Group Policy on Windows systems. In the absence of mandatory multi-factor authentication for remote access (MFA is only "recommended," per section 4 of the same policy), lockout is the primary mechanism limiting how many credential guesses an attacker can make against a single account, making it a compensating control for the missing MFA requirement.
Category: Technical
Function: Compensating
Asset(s) Protected: Windows domain user accounts, compensating for the absence of mandatory MFA on remote access
Source: Artifact 3 - Password Policy document, sections 2 and 4
```

```
Control ID: C-011
Control Name: Endpoint Antivirus (Sophos Central)
Description: Sophos Endpoint Protection is deployed to 372 of 387 managed devices (all Windows 10/11 workstations), with 88.1% carrying current signatures. The console log shows the product actively identifying and acting on threats in the last 30 days (adware quarantined, a cryptomining PUA blocked, a phishing URL blocked, a trojan quarantined), demonstrating a working detection capability with corrective quarantine action for the endpoint population it covers.
Category: Technical
Function: Detective
Asset(s) Protected: Windows 10/11 workstations (372 devices) - excludes Windows/Linux servers, macOS and mobile devices
Source: Artifact 4 - Sophos Antivirus Status Report
```

```
Control ID: C-012
Control Name: Nightly Backup Job (Veeam)
Description: A Veeam "Nightly-Full" job performs a full backup of six critical VMs (ehr-srv-01, ehr-db-01, billing-srv-01, ad-dc-01, file-srv-01, web-srv-01) every night at 02:00 to a NAS device, with 14 days of retention. This is the mechanism by which MedDefense could restore the EHR application, EHR database, billing system, domain controller, file shares and web portal to a working state after data loss, corruption, or a destructive incident, and a restore of file-srv-01 was demonstrated successfully 8 months ago.
Category: Technical
Function: Corrective
Asset(s) Protected: ehr-srv-01, ehr-db-01, billing-srv-01, ad-dc-01, file-srv-01, web-srv-01
Source: Artifact 5 - Backup Configuration
```

```
Control ID: C-013
Control Name: Uniformed Security Guard - Main Entrance
Description: ClearView Security provides one uniformed guard at the MedDefense Central main entrance, Monday through Friday from 07:00 to 19:00. A visible, uniformed guard presence at the sole staffed entry point is a classic deterrent: its primary value is discouraging an individual from attempting unauthorized entry in the first place, independent of the specific registration duties performed once someone approaches.
Category: Physical
Function: Deterrent
Asset(s) Protected: MedDefense Central main entrance and lobby
Source: Artifact 6 - Physical Security Contract (ClearView Security)
```

```
Control ID: C-014
Control Name: Visitor Registration and Badge Verification
Description: As part of the same contract, the guard performs visitor registration and badge verification at the sign-in desk, which is the specific procedural mechanism that stops an unregistered or unbadged individual from proceeding past the lobby during staffed hours. This is distinct from the guard's deterrent presence: it is the actual gatekeeping action taken at the point of entry.
Category: Physical
Function: Preventive
Asset(s) Protected: MedDefense Central main entrance and lobby, during staffed hours (weekdays 07:00-19:00)
Source: Artifact 6 - Physical Security Contract (ClearView Security)
```

```
Control ID: C-015
Control Name: CCTV Camera System
Description: MedDefense Central operates 4 analog cameras (main entrance x2, ER entrance, parking garage entrance) recording to a 30-day local DVR, and Westside Clinic operates 1 camera at its front entrance recording to a local SD card. This footage allows after-the-fact review of who entered or exited a covered area, supporting incident investigation even though it is only self-monitored rather than actively watched, and does not cover the server room, network closets, or administrative wing.
Category: Physical
Function: Detective
Asset(s) Protected: MedDefense Central entrances and parking garage entrance; Westside Clinic front entrance
Source: Artifact 6 - Physical Security Contract, camera system notes
```

```
Control ID: C-016
Control Name: Security Awareness Training Program
Description: "CyberSafe Basics" is a mandatory annual online training module covering password hygiene, phishing recognition, physical security awareness (tailgating, clean desk) and reporting suspicious activity. Where completed, it is intended to reduce the likelihood that an employee falls for a phishing email, shares a credential, or allows tailgating, i.e. it works before an incident occurs by shaping staff behavior, even though current completion rates are uneven across sites (94% Corporate HQ, 71% MedDefense Central, 58% Westside Clinic).
Category: Administrative
Function: Preventive
Asset(s) Protected: All staff across Corporate HQ, MedDefense Central and Westside Clinic
Source: Artifact 7 - Training Records
```

---

## 3. Control Summary Matrix

The matrix below places each Control ID in the cell corresponding to its category and function. An empty cell does not necessarily mean no protection whatsoever exists in that area; it means no evidenced control of that specific type was found in the artifacts reviewed, and should be read alongside the separate gap analysis as a candidate area for improvement.

|                    | Preventive                            | Detective                  | Corrective | Compensating | Deterrent |
| ------------------ | -------------------------------------- | --------------------------- | ---------- | ------------ | --------- |
| **Technical**      | C-001, C-002, C-003, C-005, C-006, C-008 | C-004, C-007, C-011          | C-012      | C-010        | —         |
| **Administrative** | C-009, C-016                          | —                            | —          | —            | —         |
| **Physical**       | C-014                                 | C-015                        | —          | —            | C-013     |

**Observations on the matrix:**

- **Technical/Deterrent is empty:** no technical control (e.g., a login banner warning of monitoring, or visible network-level deception) was evidenced. Deterrence is currently achieved only through the physical guard presence.
- **Administrative/Detective, Administrative/Corrective and Administrative/Compensating are empty:** the only administrative controls evidenced (password policy, security awareness training) are preventive in nature. No documented incident response plan, disciplinary process, or compensating administrative procedure was provided in the artifacts.
- **Physical/Corrective and Physical/Compensating are empty:** no evidenced physical control restores a damaged asset or compensates for a missing physical safeguard (for example, there is no fire suppression, environmental control, or alternate site arrangement documented for the server room).
- **Technical is the most densely populated category**, reflecting that most documented controls to date are IT-configuration based rather than procedural or physical.
