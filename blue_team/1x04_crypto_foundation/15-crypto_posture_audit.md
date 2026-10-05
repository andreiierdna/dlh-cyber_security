# Task 15 — Crypto Posture Audit

## Scope

Task 0 contains **21 data-state cells: 3 Adequate, 3 Weak, and 15 Absent**. The 18 Weak/Absent cells below are findings. Recommendations are target-state controls; they are not claims of completed deployment.

## EHR patient records

### CRYPTO-001 — EHR data at rest
- **Data Category / State:** Patient medical records / At rest
- **Current Protection:** None; PostgreSQL 14 is on unencrypted ext4.
- **Vulnerability / Risk:** Finding 003 / RISK-002
- **Algorithm Assessment:** Absent; no algorithm protects database files, WAL, temporary files, or offline media.
- **Recommended Protection:** LUKS2 AES-XTS with a 512-bit XTS key (two AES-256 keys); AES-256-GCM for selected application-encrypted fields.
- **Encryption Level:** T13 **volume**, plus **record** for selected PHI.
- **Key Management:** `db-kek` in HSM-backed KMS; wrapped unlock/record keys in the vault; offline recovery slot and LUKS header backup; annual KEK rotation.
- **Priority:** **Phase 1**

### CRYPTO-002 — EHR data in transit
- **Data Category / State:** Patient medical records / In transit
- **Current Protection:** PostgreSQL TLS is optional; the portal permits TLS 1.0 and has a near-expiry certificate.
- **Vulnerability / Risk:** Findings 003, 005, 013 / RISK-002
- **Algorithm Assessment:** Inadequate; optional TLS and TLS 1.0 permit plaintext or obsolete sessions.
- **Recommended Protection:** Require TLS 1.2/1.3 with ECDHE and AES-256-GCM or ChaCha20-Poly1305; require certificate verification and renew the portal certificate.
- **Encryption Level:** Transport, complementing T13 volume/record protection.
- **Key Management:** Portal private key in the external vault with automated renewal; database certificates from the approved CA; no plaintext private keys in configuration.
- **Priority:** **Immediate**

### CRYPTO-003 — EHR data in use
- **Data Category / State:** Patient medical records / In use
- **Current Protection:** Plaintext in application memory and at unlocked nurse sessions.
- **Vulnerability / Risk:** Finding 003 / RISK-002, RISK-006
- **Algorithm Assessment:** No ordinary cipher protects data while an authorized application displays it.
- **Recommended Protection:** AES-256-GCM record encryption for selected PHI, decrypted only for the authorized workflow; enforce automatic screen lock and least privilege.
- **Encryption Level:** T13 **record** for selected fields.
- **Key Management:** Application identity alone may unwrap record DEKs through KMS; database administrators receive no decrypt permission; annual DEK rotation.
- **Priority:** **Phase 2**

## Billing data

### CRYPTO-004 — Billing data at rest
- **Data Category / State:** Financial and billing data / At rest
- **Current Protection:** None; MySQL files are readable from unencrypted ext4.
- **Vulnerability / Risk:** Findings 001, 002 / RISK-005
- **Algorithm Assessment:** Absent; root or offline disk access exposes files. Encryption does not repair the RCE-to-root chain.
- **Recommended Protection:** LUKS2 AES-XTS with a 512-bit XTS key; AES-256-GCM for SSNs and selected identifiers.
- **Encryption Level:** T13 **volume**, plus **record** for selected values.
- **Key Management:** HSM-backed KMS/vault pattern used for EHR; separate billing service identity, recovery material, and tested escrow.
- **Priority:** **Phase 1**

### CRYPTO-005 — Billing data in transit
- **Data Category / State:** Financial and billing data / In transit
- **Current Protection:** Plaintext MySQL; SSL is not enforced.
- **Vulnerability / Risk:** Finding 006 / RISK-005
- **Algorithm Assessment:** Absent; credentials and billing records can cross the flat network in plaintext.
- **Recommended Protection:** Require mutually authenticated TLS 1.2/1.3 with ECDHE and AES-256-GCM or ChaCha20-Poly1305; reject non-TLS sessions.
- **Encryption Level:** Transport, complementing T13 volume/record protection.
- **Key Management:** Issue server/client certificates from the approved CA; private keys restricted to service identities and rotated before expiry.
- **Priority:** **Immediate**

### CRYPTO-006 — Billing data in use
- **Data Category / State:** Financial and billing data / In use
- **Current Protection:** None documented.
- **Vulnerability / Risk:** Findings 001, 002 / RISK-005, RISK-006
- **Algorithm Assessment:** No general-purpose cipher protects values while the billing application legitimately processes them.
- **Recommended Protection:** AES-256-GCM application-side encryption for SSNs and selected identifiers; decrypt only inside authorized transactions.
- **Encryption Level:** T13 **record**.
- **Key Management:** Billing application identity unwraps versioned DEKs through KMS; database-only and interactive administrator identities cannot decrypt.
- **Priority:** **Phase 2**

## Medical images

### CRYPTO-007 — PACS images at rest
- **Data Category / State:** DICOM medical images / At rest
- **Current Protection:** None; images and embedded identifiers are plaintext on `pacs-srv-01`.
- **Vulnerability / Risk:** Finding 024 / RISK-009
- **Algorithm Assessment:** Absent.
- **Recommended Protection:** Volume encryption using AES-XTS with two 256-bit AES keys, covering repository, metadata, cache, and temporary storage.
- **Encryption Level:** T13 **volume**.
- **Key Management:** KMS-wrapped volume key; escrowed recovery key; Radiology/IT-controlled unlock and tested restart/restore procedure.
- **Priority:** **Phase 1**

### CRYPTO-008 — DICOM images in transit
- **Data Category / State:** DICOM medical images / In transit
- **Current Protection:** None on TCP/4242 and TCP/11112.
- **Vulnerability / Risk:** Findings 004, 024 / RISK-009
- **Algorithm Assessment:** Absent; PHI and images traverse the network in cleartext.
- **Recommended Protection:** Vendor-supported DICOM TLS 1.2+ using ECDHE with AES-256-GCM; use a managed TLS tunnel only where the certified legacy endpoint cannot support DICOM TLS.
- **Encryption Level:** Transport, paired with T13 volume protection.
- **Key Management:** Device certificates from the approved CA; protected PACS private keys; documented renewal coordinated with Radiology and the MRI vendor.
- **Priority:** **Phase 1**

### CRYPTO-009 — PACS images in use
- **Data Category / State:** DICOM medical images / In use
- **Current Protection:** None documented while images are decoded and displayed.
- **Vulnerability / Risk:** Finding 024 / RISK-009
- **Algorithm Assessment:** No standalone algorithm can keep an image encrypted while an authorized viewer renders it.
- **Recommended Protection:** Keep caches/temp objects under AES-256-XTS volume protection; decrypt only in the approved PACS process and enforce session locking and least privilege.
- **Encryption Level:** T13 **volume**; no separate in-use encryption boundary is justified.
- **Key Management:** PACS service identity receives unlock access; recovery key remains escrowed and unavailable to ordinary radiology accounts.
- **Priority:** **Phase 2**

## Credentials

### CRYPTO-010 — Credentials at rest
- **Data Category / State:** AD and application credentials / At rest
- **Current Protection:** NT hashes use MD4; application password storage is not evidenced.
- **Vulnerability / Risk:** Finding 018 / RISK-003
- **Algorithm Assessment:** MD4-based NT hashes are inadequate for password protection.
- **Recommended Protection:** Eliminate NTLM where compatibility permits; use Kerberos AES-256 and Argon2id (minimum 19 MiB, 2 iterations, parallelism 1, unique 128-bit salt) for MedDefense-controlled application passwords.
- **Encryption Level:** Record/credential.
- **Key Management:** AD manages Kerberos keys; password hashes need salts, not decryptable keys; service-account secrets belong in the external vault with scoped access.
- **Priority:** **Immediate**

### CRYPTO-011 — Credentials in transit
- **Data Category / State:** AD and application credentials / In transit
- **Current Protection:** Kerberos permits DES/RC4; LDAP signing is not required.
- **Vulnerability / Risk:** Findings 007, 018 / RISK-003
- **Algorithm Assessment:** DES is broken and RC4 is obsolete; unsigned LDAP permits relay/manipulation.
- **Recommended Protection:** Kerberos AES-256/AES-128 only; require LDAP signing or LDAPS over TLS 1.2+ with ECDHE and AES-GCM.
- **Encryption Level:** Transport/authentication.
- **Key Management:** Rotate service-account keys after removing RC4/DES; domain controllers use CA-issued certificates with monitored renewal.
- **Priority:** **Immediate**

### CRYPTO-012 — Credentials in use
- **Data Category / State:** AD and application credentials / In use
- **Current Protection:** No credential-memory isolation is evidenced.
- **Vulnerability / Risk:** Findings 007, 018 / RISK-003
- **Algorithm Assessment:** Encryption must terminate for authentication; legacy reusable secrets increase exposure.
- **Recommended Protection:** Windows Credential Guard for compatible systems, Kerberos AES-256 tickets, short-lived service credentials, and no plaintext secrets in scripts.
- **Encryption Level:** Credential/process isolation; not a T13 storage boundary.
- **Key Management:** External vault issues scoped short-lived credentials; rotate exposed account keys immediately and audit vault/Kerberos use.
- **Priority:** **Phase 1**

## Backup data

### CRYPTO-013 — Backups at rest
- **Data Category / State:** Backup data / At rest
- **Current Protection:** None on NAS-01; supported NAS AES-256-CBC is disabled and would share the NAS failure domain.
- **Vulnerability / Risk:** Finding 015 / RISK-007
- **Algorithm Assessment:** Absent; NAS compromise exposes every backup. NAS-local CBC alone would not provide independent recovery.
- **Recommended Protection:** AES-256-GCM backup-set encryption on `backup-srv-01` before upload to NAS-01 and immutable offsite storage.
- **Encryption Level:** T13 **file/backup-set**.
- **Key Management:** New DEK per set; `backup-kek` in independent HSM-backed KMS; retain old versions; offline/offsite catalog and key escrow.
- **Priority:** **Immediate**

### CRYPTO-014 — Backups in transit
- **Data Category / State:** Backup data / In transit
- **Current Protection:** No encrypted backup transport is documented.
- **Vulnerability / Risk:** Finding 015 / RISK-007
- **Algorithm Assessment:** Absent.
- **Recommended Protection:** Send already AES-256-GCM-encrypted backup sets over TLS 1.3 (TLS 1.2 minimum) using ECDHE and AES-GCM/ChaCha20-Poly1305.
- **Encryption Level:** T13 **file**, plus transport.
- **Key Management:** Backup service certificate and wrapped set keys reside outside NAS-01; only the backup service and approved recovery operators may unwrap.
- **Priority:** **Immediate**

### CRYPTO-015 — Backups in use
- **Data Category / State:** Backup data / In use
- **Current Protection:** No isolation is documented during verification or restore.
- **Vulnerability / Risk:** Finding 015 / RISK-007
- **Algorithm Assessment:** Restored data must become plaintext; perpetual in-use encryption is not operationally possible.
- **Recommended Protection:** Keep AES-256-GCM sets encrypted until an approved isolated restore job; restrict and erase restore staging after validation.
- **Encryption Level:** T13 **file/backup-set**.
- **Key Management:** Time-bound recovery identity unwraps only required DEKs; dual approval, KMS audit logging, and quarterly restore tests.
- **Priority:** **Phase 1**

## Email

### CRYPTO-016 — Email in use
- **Data Category / State:** O365 email / In use
- **Current Protection:** No message-level control; physicians sometimes send PHI in ordinary messages.
- **Vulnerability / Risk:** No direct scan finding / RISK-006
- **Algorithm Assessment:** TLS and provider disk encryption end when an authorized user opens or forwards a message.
- **Recommended Protection:** Microsoft Purview Message Encryption for PHI; require the provider's current authenticated-encryption baseline and validate it rather than asserting a tenant-selectable cipher mode that OME does not expose.
- **Encryption Level:** T13 **record/message**.
- **Key Management:** Microsoft-managed content keys; MedDefense governs decrypt rights, tenant policy, MFA, revocation, and audit. Use S/MIME only if certificate ownership/interoperability requires it.
- **Priority:** **Phase 1**

## VPN traffic

### CRYPTO-017 — VPN-derived data at rest
- **Data Category / State:** Site-to-site VPN traffic / At rest
- **Current Protection:** Tunnel encryption ends at the gateways; no control is documented for stored payloads or captures.
- **Vulnerability / Risk:** Finding 014 / RISK-010
- **Algorithm Assessment:** AES-256/SHA-256 protects transit adequately but provides no at-rest protection after termination.
- **Recommended Protection:** Apply each destination's T13 storage control; encrypt authorized packet captures/files with AES-256-GCM before retention.
- **Encryption Level:** Destination-specific T13 volume/file/record level.
- **Key Management:** Destination KMS policies apply; capture DEKs are wrapped in KMS, access-logged, retained only as required, then destroyed.
- **Priority:** **Phase 2**

### CRYPTO-018 — VPN traffic in use
- **Data Category / State:** Site-to-site VPN traffic / In use
- **Current Protection:** None after gateways decrypt packets.
- **Vulnerability / Risk:** Finding 014 / RISK-010
- **Algorithm Assessment:** The tunnel's AES-256 is adequate in transit, but cannot protect plaintext inside an authorized destination process.
- **Recommended Protection:** Preserve end-to-end application TLS 1.2/1.3 with ECDHE and AES-GCM/ChaCha20-Poly1305 across the VPN; use record encryption for sensitive application data.
- **Encryption Level:** Transport plus destination-specific T13 record protection.
- **Key Management:** Application certificates/keys in the vault with automated renewal; retain unique VPN PSKs in the vault and rotate every 90 days.
- **Priority:** **Phase 2**

## Posture score

**100% remediation coverage:** all **18 of 18** Weak/Absent cells now have a defined remediation path; the other **3 of 21** cells were already Adequate. This score measures planning coverage, **not implementation**. Current adequate protection remains **14.3% (3/21)** until controls are deployed and validated.

## Top 3 crypto risks

1. **CRYPTO-010/011 — Active Directory credentials:** RISK-003 is **20/25**. DES/RC4 and unsigned LDAP can turn stolen credentials into enterprise authority and ransomware deployment.
2. **CRYPTO-004/005 — Billing data:** RISK-005 is **20/25**. Plaintext financial data sits on a host with a proven RCE-to-root chain and prior compromise; encryption must accompany host remediation.
3. **CRYPTO-001/002 — EHR records:** RISK-002 is **15/25** with modeled inherent ALE of **$3.025M/year**. Unencrypted storage and optional transport encryption expose MedDefense's highest-value PHI.
