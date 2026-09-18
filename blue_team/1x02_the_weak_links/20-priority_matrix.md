# Task 20 — The Priority Matrix

## Executive Priority

MedDefense has **24 actionable vulnerability findings** requiring remediation. The remediation program is divided into four firm deadlines:

* **Immediate — 24–48 hours:** contain Critical attack paths and patient-safety exposures.
* **Short-term — 7 days:** eliminate weaponized or easily exploitable High-risk weaknesses and imminent operational failures.
* **Medium-term — 30 days:** complete significant configuration hardening and controlled security updates.
* **Long-term — 90 days:** complete migrations and architectural changes that require vendor, clinical, or enterprise coordination.

Cost figures below are **planning estimates**, not vendor quotes. They assume existing MedDefense staff perform routine administration while specialist/vendor engineering, licensing, hardware and implementation work are charged to the security program. Costs for overlapping changes are counted incrementally to avoid double-counting.

---

# Immediate — 24–48 Hours

| Finding | Description                                                                                                         | Remediation Action                                                                                                                                                        | Owner                                         |         Estimated Cost |
| ------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ---------------------: |
| **004** | Windows XP MRI workstation exposes weaponized BlueKeep, EternalBlue and MS08-067 vulnerabilities without isolation. | Move `WS-RAD-01` into a dedicated default-deny MRI VLAN; allow only required PACS/vendor flows, block unnecessary SMB/RDP, and enable IPS/monitoring as virtual patching. | IT + Security + Radiology/Biomedical + Vendor |            **$25,000** |
| **003** | `ehr-db-01` accepts PostgreSQL connections from the entire `10.10.0.0/16` network.                                  | Replace broad `pg_hba.conf` access with explicit approved sources, restrict TCP/5432 by firewall/ACL, and limit PostgreSQL listening interfaces.                          | IT/Database + Security + EHR Owner            |             **$4,000** |
| **007** | LDAP signing is not required on the primary Domain Controller.                                                      | Audit unsigned LDAP binds, remediate dependent clients, enforce LDAP signing on Domain Controllers, and begin removal of SMBv1.                                           | IT/Active Directory + Security                |             **$5,000** |
| **016** | Philips IntelliVue management and HL7 interfaces are broadly reachable from the flat network.                       | Place IntelliVue monitors in a protected medical-device VLAN; allow only documented central-monitoring, HL7 and biomedical-management flows.                              | IT + Security + Biomedical/Clinical + Vendor  |            **$15,000** |
| **001** | Apache `mod_lua` CVE-2021-44790 permits unauthenticated remote code execution on `billing-srv-01`.                  | Apply a supported Apache security package containing the CVE fix after billing-application testing; back up and validate before reopening service.                        | IT + Security + Finance App Owner             |             **$4,000** |
| **002** | CVE-2019-0211 can escalate the Finding 001 web-service foothold to root.                                            | Remediate in the same Apache maintenance window as Finding 001 and validate that the privilege-escalation path is removed.                                                | IT + Security                                 | **$1,000 incremental** |

**Immediate subtotal: $54,000**

The MRI is first because T16 identifies it as a Critical system with multiple weaponized remote exploits. The database, Domain Controller and medical monitors follow because they expose Critical clinical or identity infrastructure. Findings 001 and 002 are remediated together because they form one practical RCE-to-root attack chain.

---

# Short-Term — Within 7 Days

| Finding | Description                                                                                       | Remediation Action                                                                                                                                       | Owner                                  | Estimated Cost |
| ------- | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- | -------------: |
| **008** | `print-srv-01` is an EOL Windows Server with weaponized PrintNightmare exposure.                  | Install applicable PrintNightmare security updates/ESU fixes, disable the Print Spooler where unnecessary, and restrict Point-and-Print exposure.        | IT/Windows + Security                  |     **$4,000** |
| **010** | BD Alaris pumps use default `admin/admin` credentials and are insufficiently isolated.            | Replace default credentials using vendor-supported procedures; move pumps to a dedicated VLAN with explicit clinical communication rules.                | Biomedical + IT + Security + BD Vendor |    **$12,000** |
| **015** | NAS-01 DSM management is accessible throughout the internal network and protects primary backups. | Restrict DSM access to dedicated backup-management hosts, require HTTPS and hardened administrator authentication, and block general workstation access. | IT/Backup + Security                   |     **$4,000** |
| **029** | Undocumented Grafana 8.2.0 host exposes publicly exploitable CVE-2021-43798.                      | Identify the owner immediately; patch Grafana to a supported release or isolate and decommission the host if no approved business purpose exists.        | IT + Security + Westside Owner         |     **$2,000** |
| **013** | Patient-portal TLS certificate expires in 23 days and has no automated renewal.                   | Renew the certificate immediately and deploy monitored automated renewal with expiry alerting.                                                           | IT/Web + Security                      |     **$1,000** |

**Short-term subtotal: $23,000**

**Cumulative through Day 7: $77,000**

---

# Medium-Term — Within 30 Days

| Finding | Description                                                                       | Remediation Action                                                                                                                                                          | Owner                           | Estimated Cost |
| ------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- | -------------: |
| **006** | MySQL on `billing-srv-01` listens on `0.0.0.0` and is broadly reachable.          | Bind MySQL only to the required interface and restrict TCP/3306 to approved application/administrative sources.                                                             | IT/Database + Security          |     **$2,000** |
| **018** | Domain Controllers permit DES and RC4 Kerberos encryption.                        | Inventory legacy dependencies, migrate accounts/services to AES, then disable DES and RC4 domain-wide.                                                                      | IT/Active Directory + Security  |     **$4,000** |
| **009** | Billing SSH permits password authentication without adequate lockout protection.  | Move administrative SSH to managed keys or stronger authentication, disable general password login, and enforce source restrictions.                                        | IT/Linux + Security             |     **$2,000** |
| **005** | Internet-facing patient portal permits TLS 1.0.                                   | Disable TLS 1.0 and require supported TLS 1.2+ configurations after compatibility testing.                                                                                  | IT/Web + Security               |     **$1,000** |
| **012** | Patient portal lacks important browser security headers.                          | Implement CSP, HSTS, X-Frame-Options/frame restrictions and X-Content-Type-Options; validate portal functionality before production.                                        | Web/Application Team + Security |     **$1,000** |
| **017** | Tomcat default errors reveal version and internal path information.               | Disable verbose/default error output, suppress version disclosure and deploy controlled application error pages.                                                            | IT/EHR Vendor + Security        |     **$1,000** |
| **025** | AD DNS permits unrestricted zone transfers.                                       | Permit AXFR only to explicitly authorized secondary DNS servers and deny arbitrary transfer requests.                                                                       | IT/Active Directory/DNS         |     **$1,000** |
| **026** | Billing server runs an outdated Linux kernel with numerous known vulnerabilities. | Enable a supported security-maintenance path such as ESM as an interim control, apply current kernel fixes, reboot during a billing maintenance window and verify services. | IT/Linux + Security             |     **$4,000** |
| **028** | Unmanaged Linux/Jupyter/Cockpit host exists on the server subnet.                 | Restrict its network access immediately; identify its owner and business purpose, then onboard it to managed controls or decommission it by Day 30.                         | IT + Security                   |     **$3,000** |

**Medium-term subtotal: $19,000**

**Cumulative through Day 30: $96,000**

---

# Long-Term — Within 90 Days

| Finding | Description                                                                                | Remediation Action                                                                                                                                     | Owner                                        | Estimated Cost |
| ------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------- | -------------: |
| **014** | Consumer-grade Netgear router terminates Westside's trusted site-to-site VPN into Central. | Replace it with an enterprise-managed firewall/router supporting centralized logging, secure administration, granular ACLs and supported VPN controls. | Network IT + Security                        |    **$20,000** |
| **011** | `billing-srv-01` runs Ubuntu 18.04 outside standard support.                               | Migrate the billing application to a supported Ubuntu LTS platform after application, Apache and MySQL compatibility testing.                          | IT + Finance App Owner + Vendor              |    **$15,000** |
| **023** | USB mass storage is unrestricted across approximately 280 clinical workstations.           | Deploy centrally managed removable-media/device control with role-based exceptions for approved clinical workflows and full audit logging.             | Endpoint IT + Security + Clinical Operations |    **$12,000** |
| **024** | PACS DICOM communication carrying patient identifiers and images is unencrypted.           | Implement vendor-supported DICOM TLS between MRI/Radiology systems and PACS, with certificate management and interoperability testing.                 | IT/PACS + Security + Radiology + Vendor      |    **$18,000** |

**Long-term subtotal: $65,000**

---

# Full Priority Matrix Summary

| Horizon                   | Findings                                    |  Count | Estimated Cost |
| ------------------------- | ------------------------------------------- | -----: | -------------: |
| **Immediate — 24–48h**    | 004, 003, 007, 016, 001, 002                |  **6** |    **$54,000** |
| **Short-term — 7 days**   | 008, 010, 015, 029, 013                     |  **5** |    **$23,000** |
| **Medium-term — 30 days** | 006, 018, 009, 005, 012, 017, 025, 026, 028 |  **9** |    **$19,000** |
| **Long-term — 90 days**   | 014, 011, 023, 024                          |  **4** |    **$65,000** |
| **TOTAL**                 | **24 actionable findings**                  | **24** |   **$161,000** |

---

# Budget Summary

## Total Estimated Remediation Cost

**$161,000**

MedDefense's annual security budget is:

**$120,000**

Therefore:

**Budget shortfall = $161,000 - $120,000 = $41,000**

The complete remediation program would consume approximately:

**134% of the annual security budget**

and exceed available funding by approximately:

**34%**

This means MedDefense cannot fully fund every remediation in the current annual budget without additional capital or operational funding.

## Mandatory Current-Cycle Spending

All Immediate, Short-term and Medium-term work should be funded:

**Immediate:** $54,000
**Short-term:** $23,000
**Medium-term:** $19,000

**Subtotal through Day 30: $96,000**

Of the Long-term projects, **Finding 014 — replacement of the Westside consumer router — should also be funded this cycle for $20,000** because the device terminates a trusted site-to-site VPN into Central and therefore represents an architectural path into the wider MedDefense network.

**Committed program total: $116,000**

**Remaining annual budget reserve: $4,000**

The $4,000 should remain as remediation contingency for failed changes, emergency vendor assistance, replacement certificates, unexpected compatibility work or other costs discovered during the 24–48 hour and 7-day remediation windows.

## Deferred Remediations

The following three full implementations must be deferred to the next funding cycle unless MedDefense obtains an additional **$45,000**:

**Finding 011 — Ubuntu 18.04 full platform migration — $15,000.**
The full OS migration is deferred because Finding 026 provides a funded 30-day interim risk reduction through supported security maintenance and kernel patching. The migration should still be engineered and tested during the 90-day period so it is ready for execution when funding becomes available.

**Finding 023 — Enterprise USB device-control rollout — $12,000.**
The organization-wide deployment is deferred because it requires clinical workflow discovery and an exception process across approximately 280 endpoints. Security should immediately establish policy and begin pilot controls on the highest-risk systems, but broad production rollout moves to the next funded phase.

**Finding 024 — DICOM TLS implementation — $18,000.**
The full encryption project is deferred because it requires coordinated PACS, MRI, certificate and vendor interoperability work and therefore cannot be safely rushed. In the interim, the MRI/PACS environment should receive the segmentation and monitoring controls already funded under Finding 004.

**Total deferred implementation: $45,000**

The program intentionally defers **architectural work with available interim controls**, not Critical exposures with active exploit paths. MedDefense should not defer Findings 001, 002, 003, 004, 007, 008, 010, 015, 016 or 029 simply to stay within budget, because doing so would leave weaponized vulnerabilities, Critical clinical systems, enterprise identity infrastructure or ransomware recovery paths exposed.

# Final IT Director Timeline

**Today / next 48 hours:** contain the MRI, EHR database, Active Directory and Philips device networks, and patch the chained Apache vulnerabilities.

**By Friday / Day 7:** address PrintNightmare, Alaris default credentials, NAS management exposure, vulnerable Grafana and the expiring patient-portal certificate.

**By Day 30:** complete database, identity, SSH, TLS, web, DNS, kernel and shadow-IT hardening.

**By Day 90:** replace the Westside consumer VPN router and complete engineering for the remaining platform-migration, USB-control and DICOM-encryption projects.

The operating principle is simple: **spend the limited budget first where exploitation can become clinical, identity-wide or unrecoverable enterprise impact; defer only changes for which a defensible interim control exists.**
