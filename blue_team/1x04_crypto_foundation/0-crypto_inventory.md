# MedDefense Health Systems 
## Task 0: Data Protection Map

## 1. Purpose

This Data Protection Map inventories MedDefense's current cryptographic protection across three data states: **at rest, in transit, and in use**. It connects the current cryptographic posture to the 1x02 Vulnerability Assessment, the 1x03 Risk Register, the 1x03 Security Strategy, and the MedDefense Cryptographic Audit Notes.

---

# 2. Data Protection Map

| Data Category | At Rest | In Transit | In Use |
|---|---|---|---|
| **Patient medical records — EHR data in PostgreSQL** | **Protection:** None. PostgreSQL data is stored on an unencrypted ext4 filesystem. **Evidence:** Crypto audit notes state that the PostgreSQL data directory has no encryption layer and patient records are readable in plaintext if the disk or server is accessed. **Status:** **Absent** | **Protection:** PostgreSQL SSL is available but not enforced. Both `hostssl` and `hostnossl` connections are permitted. The related patient portal also supports obsolete TLS 1.0 alongside TLS 1.2. **Evidence:** Audit notes confirm `ssl=on` but allow non-SSL PostgreSQL connections from `10.10.0.0/16`. The patient portal supports TLS 1.0 and TLS 1.2 and does not support TLS 1.3. **Status:** **Weak** | **Protection:** None. Patient information is decrypted in application memory while clinicians view or process records. **Evidence:** Audit notes explicitly state that no additional protection exists for actively processed EHR data and also note that nurse workstations do not automatically lock. **Status:** **Absent** |
| **Financial / billing data — MySQL on `billing-srv-01`** | **Protection:** None. MySQL files reside on an unencrypted ext4 filesystem. **Evidence:** The billing database contains patient identifiers, SSNs, insurance data and billing records, while its database files are directly readable from the filesystem without MySQL credentials. **Status:** **Absent** | **Protection:** None. MySQL SSL is not enforced and the billing application currently uses the plaintext MySQL protocol over the internal network. **Evidence:** `billing-srv-01` is bound to `0.0.0.0`, does not require SSL, and the application connects in plaintext. **Status:** **Absent** | **Protection:** None documented. No cryptographic control is identified for billing information while it is actively processed by the billing application. The audit establishes plaintext storage and transport but identifies no additional in-use encryption mechanism. **Evidence:** Crypto audit notes, Financial Data section. **Status:** **Absent** |
| **Medical images — DICOM on PACS** | **Protection:** None. PACS stores DICOM images on local disk without encryption. **Evidence:** DICOM files and embedded patient identifiers are readable directly from PACS storage. **Status:** **Absent** | **Protection:** None. DICOM TLS is supported by the standard but is not configured anywhere in MedDefense. MRI, CT, X-ray, and embedded patient identifiers traverse the network in cleartext. **Evidence:** Audit notes document cleartext DICOM traffic over ports 4242 and 11112. This corresponds directly to 1x02 Finding 024 and RISK-009, which identifies unencrypted DICOM as part of the PACS/MRI risk. **Status:** **Absent** | **Protection:** None documented. Medical images must be decoded and displayed to radiology users, and no additional cryptographic protection for actively processed images is identified in the audit. **Evidence:** The PACS audit section documents unencrypted storage and transport and identifies no in-use encryption mechanism. **Status:** **Absent** |
| **Credentials — Active Directory and application passwords** | **Protection:** NTHash using MD4 for Active Directory NTLM compatibility; application-password storage is not separately documented. **Evidence:** The audit confirms that Active Directory uses NTHash/MD4 and supports multiple Kerberos encryption types. MD4-based NT hashes provide legacy compatibility but do not constitute a strong modern password-storage design. **Status:** **Weak** | **Protection:** Kerberos AES-256/AES-128, but legacy RC4 and DES remain enabled; LDAP is not encrypted by default and LDAP signing is not required. **Evidence:** Finding 018 confirmed continued DES/RC4 support, while Finding 007 confirmed weak LDAP protection. RISK-003 directly associates these weaknesses with enterprise Active Directory compromise. **Status:** **Weak** | **Protection:** None documented. Credentials and derived authentication secrets must be available to authentication processes, and no credential-memory isolation or equivalent cryptographic in-use control is documented. **Evidence:** The audit identifies storage and network authentication mechanisms but no cryptographic protection for credentials while actively used. **Status:** **Absent** |
| **Backup data — `NAS-01`** | **Protection:** None. NAS backups are stored on an unencrypted RAID-5 array. Synology AES-256-CBC shared-folder encryption is supported but is not enabled. **Evidence:** The audit confirms that all backups, including PostgreSQL and MySQL database dumps, are readable in plaintext if the NAS is compromised. This directly supports RISK-007 concerning loss or destruction of recovery data. **Status:** **Absent** | **Protection:** None documented for the backup-data transfer path. The NAS management interface is reachable over the flat production network, and no approved encrypted backup transport is identified. **Evidence:** Finding 015 and the audit notes document broad NAS reachability and the absence of a defined encryption design. **Status:** **Absent** | **Protection:** None documented. Backup data must be readable during backup verification and restoration, and no cryptographic isolation for data being actively restored or processed is documented. **Evidence:** The current backup architecture provides neither an enabled storage-encryption layer nor a documented in-use cryptographic control. **Status:** **Absent** |
| **Email — Microsoft 365 / O365** | **Protection:** BitLocker on Microsoft datacenter disks plus per-mailbox encryption using Microsoft-managed keys. **Evidence:** The audit specifically documents Microsoft's at-rest encryption for MedDefense O365 mailboxes. **Status:** **Adequate** | **Protection:** TLS 1.2 for Exchange Online connections. **Evidence:** The audit records TLS 1.2 as the current transport protection for O365. S/MIME and OME are not configured, so MedDefense lacks message-level/end-to-end encryption, but the network transport itself is encrypted. **Status:** **Adequate** | **Protection:** None beyond normal application access once a message is opened. S/MIME/OME is not configured, and sensitive PHI is sometimes sent in ordinary email messages. **Evidence:** The audit explicitly notes that individual-message encryption is not configured and that physicians sometimes email patient information without message-level encryption. **Status:** **Absent** |
| **VPN traffic — site-to-site tunnels** | **Protection:** None applicable to the live tunnel itself once traffic has been terminated; no encrypted storage control for captured VPN traffic or related stored payloads is documented. **Evidence:** The audit documents transport encryption but no at-rest protection for VPN-derived data. **Status:** **Absent** | **Protection:** IPSec using AES-256 encryption, SHA-256 integrity, IKEv2 key exchange and Diffie-Hellman Group 14. **Evidence:** Central-to-Westside and Central-to-HQ tunnels use this configuration, which the MedDefense audit records as appearing adequate. The Westside consumer router remains an infrastructure concern because its firmware history is unknown, but this does not change the strength of the configured algorithms themselves. **Status:** **Adequate** | **Protection:** None. IPSec protection ends when packets are decrypted at the VPN termination points; no cryptographic protection is documented for traffic while internal systems actively process it. **Evidence:** The audit describes tunnel protection only for the site-to-site transit path. **Status:** **Absent** |

---

# 3. Gap Summary

The Data Protection Map contains **21 cells**:

**7 data categories × 3 data states = 21 cells**

The current protection distribution is:

| Status | Cells | Percentage |
|---|---:|---:|
| **Adequate** | **3** | **14.3%** |
| **Weak** | **3** | **14.3%** |
| **Absent** | **15** | **71.4%** |
| **Total** | **21** | **100%** |

The three **Adequate** cells are O365 email at rest, O365 email in transit, and site-to-site VPN traffic in transit.

The three **Weak** cells are EHR data in transit, Active Directory credentials at rest, and Active Directory credentials in transit.

All remaining **15 cells** have no adequate cryptographic protection implemented or documented.

## Overall Cryptographic Coverage

For this inventory, a cell is considered **cryptographically covered** when some cryptographic protection is actively present, even if that protection is currently weak and requires remediation.

Therefore:

**Covered cells = Adequate + Weak**

**Covered cells = 3 + 3 = 6**

**Overall Crypto Coverage = 6 ÷ 21 × 100**

**Overall Crypto Coverage = 28.6%**

Only **14.3%** of the matrix currently has protection that can be classified as **Adequate**:

**3 ÷ 21 × 100 = 14.3%**

This means **71.4% of MedDefense's mapped data-state combinations currently have absent cryptographic protection**, while another **14.3% rely on weak or obsolete protection**.

---

# 4. Principal Cryptographic Gaps

The inventory exposes a consistent pattern across MedDefense. Systems directly controlled by MedDefense generally have significantly weaker cryptographic protection than services where encryption is provided by Microsoft or by the configured FortiGate VPN. Sarah Park's audit summarizes this condition directly: Microsoft provides the O365 encryption and the VPN tunnels are encrypted, while the patient database, billing database, medical images, backups, Active Directory authentication, and patient portal are either unencrypted or use weak protocols.

The most significant immediate gaps are therefore encryption of the EHR and billing databases at rest; mandatory encrypted PostgreSQL and MySQL connections; DICOM TLS; replacement of DES/RC4 and stronger credential protection; backup encryption with keys separated from the NAS failure domain; and removal of TLS 1.0 from the patient portal.

These issues directly connect to prior MedDefense risks. Weak Active Directory cryptography contributes to **RISK-003 — Active Directory compromise**. Unencrypted backups contribute to **RISK-007 — Backup destruction**. Cleartext DICOM contributes to **RISK-009 — PACS/MRI compromise**. The site-to-site VPN algorithms themselves are adequate, but the Westside endpoint remains part of **RISK-010** because the consumer router has an unknown firmware history and provides a trusted path toward Central.

The Security Strategy correctly establishes Project 1x04 as the mechanism for addressing these gaps. It requires MedDefense to define approved protocols and cipher suites, certificate issuance and renewal, encryption requirements for Restricted information at rest and in transit, key ownership and rotation, secrets storage, VPN standards, medical-device exceptions, and migration plans for legacy clinical systems.

---

# 5. Conclusion

MedDefense currently has effective cryptographic protection in only a small part of its environment. Of the 21 data-state combinations assessed, **3 are Adequate, 3 are Weak, and 15 are Absent**.

The resulting **overall cryptographic coverage is 28.6%**, while only **14.3% of cells have adequate protection**.

The strongest protections are externally managed O365 encryption and the AES-256 IPSec site-to-site VPN configuration. The largest deficiencies exist in MedDefense-controlled databases, PACS/DICOM, backup infrastructure, Active Directory legacy cryptography, and the patient portal.

This Data Protection Map establishes the baseline for the remainder of the Cryptographic Foundation project. Subsequent tasks should convert the identified weak and absent cells into explicit cryptographic requirements, approved algorithms, key-management standards, certificate controls, and prioritized remediation actions tied to the existing MedDefense risk register.
