# Task 19 — The Remediation Map

## Remediation Planning Principles

The eight findings prioritized in Task 17 are Findings **001, 002, 003, 004, 007, 010, 015 and 016**.

Remediation is not treated as a simple technical fix. Each action must account for testing, service availability, clinical dependencies, rollback capability and the possibility that the remediation itself may interrupt patient care or business operations.

Findings 001 and 002 affect the same Apache installation on `billing-srv-01` and should therefore be remediated in the **same maintenance window**. Findings 004, 010 and 016 affect medical technology and require additional coordination with Clinical/Biomedical Engineering and the relevant manufacturer before changes are introduced.

---

## Finding 001 — CVE-2021-44790 Apache mod_lua Buffer Overflow

Response Type: **Patch**

The scan identifies Apache 2.4.29 on `billing-srv-01`, confirms that `mod_lua` is loaded, and reports CVE-2021-44790 as an unauthenticated remote-code-execution risk. Apache states that CVE-2021-44790 affects versions through 2.4.51 and was corrected in Apache 2.4.52.

Patch Source: **Use the supported Ubuntu/Canonical package update path for Apache and verify that the installed security package contains the CVE-2021-44790 fix. If the current Ubuntu 18.04 package source cannot provide a supported security update because the operating system is outside standard support, use Ubuntu Pro/ESM or migrate the server to a supported Ubuntu LTS release rather than installing an unmanaged Apache build. Apache upstream identifies 2.4.52 as containing the fix.**

Prerequisites: **Create a verified VM/system backup; export `/etc/apache2`, application configuration, SSL configuration and billing application files; document the current Apache packages and loaded modules; clone or stage the billing application in a test environment; perform billing transaction, database connectivity, authentication and reporting tests against the updated Apache build; notify Finance and IT of the maintenance window.**

Rollback Plan: **Preserve the pre-change VM snapshot or full server backup and package/configuration inventory. If the upgraded Apache service fails to start or billing functionality fails validation, restore the previous VM snapshot or approved package/configuration state, re-enable the previous service, verify billing database consistency and reopen the change as a failed deployment.**

Operational Risk: **The Apache update may introduce module compatibility problems, deprecated configuration directives or application behavior changes. A failed upgrade could make the billing application unavailable and interrupt claims processing. Rolling back without checking database transactions could also create application/database inconsistency if transactions occurred during the maintenance period.**

Timeline: **Immediate**

Owner: **IT, with Security validation and Finance application-owner testing**

Cost Estimate: **$1-10K**

---

## Finding 002 — CVE-2019-0211 Apache Privilege Escalation

Response Type: **Patch**

Finding 002 affects the same Apache 2.4.29 installation. The scan explicitly documents the chain in which Finding 001 provides execution as `www-data` and CVE-2019-0211 then permits escalation to root. Apache states that CVE-2019-0211 affects Apache 2.4.17 through 2.4.38 and that the correction was released in 2.4.39.

Patch Source: **Apply the same supported Apache/Ubuntu update used for Finding 001. The deployed version or vendor-patched package must include the CVE-2019-0211 correction. Apache upstream identifies 2.4.39 as the first fixed upstream release.**

Prerequisites: **Use the same pre-production billing test, backup, Apache configuration export and maintenance window as Finding 001. Confirm that the update fixes both CVEs so the server is not restarted twice for two related Apache changes.**

Rollback Plan: **Use the same validated rollback image and configuration backup prepared for Finding 001. Roll back both Apache fixes together rather than restoring only one component of the web stack.**

Operational Risk: **The principal remediation risk is application incompatibility or billing-service outage during the Apache change. Treating Findings 001 and 002 as independent patches would unnecessarily double change risk and downtime.**

Timeline: **Immediate**

Owner: **IT, with Security validation**

Cost Estimate: **$0-1K incremental if completed with Finding 001**

---

## Finding 003 — PostgreSQL Unrestricted Network Access

Response Type: **Configuration Change**

The current configuration permits PostgreSQL connections from the entire `10.10.0.0/16` environment through `pg_hba.conf` and sets `listen_addresses='*'`. The Gap Analysis identifies the required missing control as database-level segmentation and an allow-list principally restricting access to `ehr-srv-01`.

Change Description: **Replace the broad `host all all 10.10.0.0/16 md5` rule with explicit PostgreSQL rules allowing only documented application and administrative sources. At minimum, normal EHR application connectivity should be restricted to `ehr-srv-01` (`10.10.2.10/32`) rather than the entire `/16`. Configure the host/network firewall to permit TCP/5432 only from approved EHR application and database-administration systems. Replace `listen_addresses='*'` with the specific database interface/address required for EHR operation. Before enforcement, review PostgreSQL connection logs to identify legitimate integrations, reporting tools, backup jobs or vendor systems that also require access.**

Impact Assessment: **The main risk is unintentionally blocking a legitimate EHR integration, reporting process, backup operation or vendor-maintenance connection. Because `ehr-db-01` supports a Critical clinical application, rules should first be tested in audit/staging form, approved source IPs should be documented, and a database administrator should remain available during implementation to restore the previous `pg_hba.conf` and firewall policy if clinical application connectivity fails. The change should be performed during a controlled EHR maintenance window with Clinical Operations notified.**

Timeline: **Immediate**

Owner: **IT, with Security and Clinical/EHR application-owner validation**

Cost Estimate: **$1-10K**

---

## Finding 004 — Legacy Windows XP MRI Workstation / BlueKeep and Other CVEs

Response Type: **Compensating Control**

The MRI workstation runs Windows XP and exposes multiple weaponized vulnerabilities, including BlueKeep over TCP/3389. Microsoft did release the exceptional KB4500331 BlueKeep update for Windows XP SP3/Embedded, but MedDefense's project constraints establish that modifying the certified MRI operating-system environment cannot be treated like an ordinary desktop patch.

The previously developed MRI compensating-control strategy specifically identifies network segmentation as the highest-value control because it reduces risk without modifying the certified operating system.

Control Description: **Move `WS-RAD-01` into a dedicated MRI/Radiology VLAN protected by default-deny ACLs. Permit only explicitly required communications between the MRI and `pacs-srv-01` on documented imaging ports and approved vendor-management paths. Block ordinary workstations, Active Directory, billing, Internet access and unrelated medical-device networks unless a documented dependency exists. Place an internal firewall/IPS at the segment boundary to provide virtual-patching signatures for SMB/RDP attacks, block unnecessary TCP/445 and TCP/3389 exposure, restrict outbound communication, and generate alerts for connections outside the approved MRI-to-PACS baseline. Add dedicated network monitoring, formal exception documentation and restricted physical/removable-media access.**

This follows the existing MedDefense compensating-control strategy, which calls for a dedicated VLAN, default-deny ACLs, firewall/IPS virtual patching, monitoring, formal exception management and physical restrictions.

Residual Risk: **The Windows XP workstation remains intrinsically vulnerable, and the required MRI-to-PACS communication path remains a trusted route. Network controls can reduce reachability and lateral movement but cannot remove vulnerabilities within the certified device itself. A malicious update, permitted vendor connection, physical attack or exploit carried through an explicitly allowed PACS flow could still create compromise. Long-term replacement or manufacturer-approved modernization remains necessary.**

Timeline: **Immediate**

Owner: **IT and Security, with Clinical/Radiology and Vendor approval**

Cost Estimate: **$10-50K**

---

## Finding 007 — LDAP Signing Not Required on Active Directory

Response Type: **Configuration Change**

Finding 007 confirms that `ad-dc-01` does not require LDAP signing. Microsoft recommends identifying clients making unsigned LDAP binds before enforcement, configuring clients to negotiate or require signing, and then setting **Domain controller: LDAP server signing requirements = Require signing** on the Domain Controllers policy.

Change Description: **First enable/review LDAP diagnostic logging and inventory every application, appliance and service making unsigned LDAP binds. Remediate or reconfigure those clients to use signed LDAP or LDAPS. Then configure Group Policy under the Domain Controllers policy so `Domain controller: LDAP server signing requirements` is set to `Require signing`. Where applications use LDAP clients, configure `Network security: LDAP client signing requirements` to request or require signing as appropriate. Also remove SMBv1 from `ad-dc-01` after confirming no required legacy dependency.**

Impact Assessment: **Applications, appliances, scripts or medical systems that perform unsigned LDAP binds may lose authentication or directory connectivity after enforcement. Microsoft explicitly recommends identifying such clients first because requiring signing can break incompatible LDAP applications. The change should therefore follow a short audit/remediation period rather than being switched on blindly. If a critical clinical dependency is discovered, document a temporary exception for that source while the application owner or vendor remediates it; do not permanently return the entire Domain Controller to unsigned LDAP.**

Timeline: **7 days**

Owner: **IT / Active Directory team, with Security oversight**

Cost Estimate: **$1-10K**

---

## Finding 010 — BD Alaris Default Credentials and Medical-Device Exposure

Response Type: **Configuration Change**

The scan reports BD Alaris software 12.1.2 and confirms that all seven tested pumps responded to default `admin/admin` management credentials. As established in the previous analysis, the specific CVE-2020-25165 mapping should not drive this remediation; the actionable MedDefense conditions are default credentials and inadequate network isolation.

BD's current Alaris guidance recommends restricting traffic to required endpoints and ports, placing PCUs on their own VLAN, enabling an authentication challenge for network configuration changes, rotating network credentials and monitoring for unexpected network activity.

Change Description: **Coordinate with Biomedical Engineering and BD to remove or replace the `admin/admin` default management credentials with unique controlled credentials supported by the device. Place the Alaris fleet on a dedicated medical-device VLAN and implement default-deny ACLs. Permit only documented clinical infrastructure. BD's published guidance states that the PCU requires DNS, DHCP and Systems Manager communication on port 3613 and highly recommends a separate VLAN; firewall rules should therefore be based on the actual MedDefense Alaris architecture rather than broad access from the hospital network. Enable the vendor-supported authentication challenge for network configuration changes, rotate wireless/network credentials and monitor the VLAN for unexpected communication.**

Impact Assessment: **Incorrect ACLs or credential changes could prevent pumps from communicating with Systems Manager, receiving configuration/dataset updates or participating in interoperability workflows. The change must therefore be validated on a small non-patient-care test group before fleet-wide rollout. Nursing and Biomedical Engineering must confirm that sufficient pumps remain available while batches are reconfigured. Emergency rollback consists of restoring the last known-good VLAN/ACL configuration and vendor-approved device settings—not reintroducing default credentials as a permanent fix.**

Timeline: **7 days**

Owner: **Clinical/Biomedical Engineering and IT, with Security and BD Vendor support**

Cost Estimate: **$10-50K**

---

## Finding 015 — Synology NAS Management Interface Accessible

Response Type: **Configuration Change**

The scan confirms that DSM management ports 5000/5001 are reachable from the entire internal network and that the NAS stores MedDefense server backups. GAP-004 further establishes that the NAS is Critical recovery infrastructure sharing the same network and physical failure domain as production.

Synology DSM supports firewall rules that allow or deny specific ports based on specific source IP addresses, including a default-deny posture for requests not matching an allow rule.

Change Description: **Create a dedicated backup-management network or management-source allow-list. Permit DSM HTTPS management on TCP/5001 only from designated backup-administrator workstations/jump hosts and required management systems. Deny TCP/5000/5001 from ordinary clinical, administrative and medical-device networks. Disable plain HTTP management on TCP/5000 where operationally possible and require HTTPS. Review privileged DSM accounts, remove unused/default administrative accounts, require strong authentication/MFA where supported, and separate backup-administration credentials from normal production identities. In parallel, plan encryption of backup data and an immutable/offline or offsite recovery copy so NAS compromise cannot destroy the only usable recovery set.**

Impact Assessment: **An incorrect firewall rule could lock administrators or Veeam-related services out of the NAS and interrupt nightly backups. Before enforcement, record every legitimate connection to NAS-01, validate Veeam traffic separately from DSM administration, export the DSM configuration, and ensure console/local recovery access is available. Apply the allow rules before the final deny rule because Synology warns that firewall rule priority matters and administrators can otherwise block their own management access. **

Timeline: **7 days**

Owner: **IT / Backup team, with Security oversight**

Cost Estimate: **$1-10K for management isolation; $10-50K if immutable/offsite recovery is implemented simultaneously**

---

## Finding 016 — Philips IntelliVue Management and HL7 Interfaces

Response Type: **Compensating Control**

The scan identifies 13 IntelliVue monitors exposing TCP/80, TCP/443 and HL7 TCP/2575 across the internal network, with no meaningful authentication beyond network trust. GAP-002 states that MedDefense currently lacks enforced medical-device VLANs, default-deny internal access, dedicated device monitoring and documented recovery procedures.

Philips documentation recommends operating IntelliVue systems on logically or physically isolated networks/VLANs and using routers/firewalls to separate those networks from other hospital systems.

Control Description: **Create a dedicated Philips/clinical-monitoring VLAN or protected medical-device security zone. Apply default-deny firewall rules and permit only the exact flows required between the monitors, Philips central monitoring infrastructure, approved HL7/EHR integration systems, DNS/NTP services where required and authorized biomedical-management workstations. Block ordinary employee workstations and unrelated servers from TCP/80, TCP/443 and TCP/2575 on the monitors. Monitor the VLAN for scanning, unexpected management connections, unusual HL7 traffic or devices communicating outside their approved clinical peers. Where Philips-supported firmware or access-control updates exist, evaluate them through Biomedical Engineering and the vendor separately rather than making unsupported device modifications.**

Residual Risk: **The devices and their permitted clinical protocols remain reachable by specifically authorized systems, so compromise of an approved monitoring server, integration engine or biomedical workstation could still create a path to the monitors. Network isolation also cannot repair vulnerabilities inside device firmware. Clinical availability risk remains if a firewall, switch or ACL fails, which makes redundant network design and vendor-tested rules important.**

Timeline: **7 days**

Owner: **IT and Security, with Clinical/Biomedical Engineering and Philips Vendor validation**

Cost Estimate: **$10-50K**

---

# Remediation Priority Map

| Priority | Finding | Primary Action                                      | Timeline  | Principal Operational Risk                             |
| -------- | ------- | --------------------------------------------------- | --------- | ------------------------------------------------------ |
| 1        | 001     | Patch Apache for CVE-2021-44790                     | Immediate | Billing application outage                             |
| 2        | 002     | Patch Apache for CVE-2019-0211 in same change       | Immediate | Same billing maintenance risk                          |
| 3        | 003     | Restrict PostgreSQL to approved EHR sources         | Immediate | Blocking legitimate EHR/database integration           |
| 4        | 004     | Isolate MRI with VLAN/ACL/IPS compensating controls | Immediate | Disrupting MRI-to-PACS workflow                        |
| 5        | 007     | Require LDAP signing after unsigned-bind audit      | 7 days    | Breaking legacy LDAP-dependent applications            |
| 6        | 015     | Restrict NAS management and isolate recovery access | 7 days    | Blocking backup jobs or administrative recovery access |
| 7        | 016     | Segment and monitor Philips IntelliVue fleet        | 7 days    | Loss of patient-monitoring integration                 |
| 8        | 010     | Remove Alaris default credentials and isolate fleet | 7 days    | Pump/System Manager interoperability disruption        |

# Overall Remediation Strategy

The eight findings require three different remediation approaches. **Findings 001 and 002 should be patched together** because they affect the same Apache server and form a direct RCE-to-root chain. **Findings 003, 007, 010 and 015 require controlled configuration changes** in which the major risk is accidentally blocking legitimate clinical or business communication. **Findings 004 and 016 require compensating controls** because clinical-device constraints make ordinary enterprise patching insufficient or operationally unsafe.

The common implementation principle is therefore **test → back up/configure rollback → communicate → change → validate → monitor**. MedDefense should not accept continued broad connectivity merely to avoid change risk, but neither should it deploy segmentation or security settings without first documenting required clinical traffic. The goal is to reduce attack paths while ensuring that the remediation itself does not become a patient-care or business-continuity incident.
