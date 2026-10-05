# Task 14 — Hardware Security and Key Management

**Recommendation:** Use existing endpoint hardware security and a shared, HSM-backed cloud KMS for MedDefense's database and backup wrapping keys—not a dedicated HSM appliance.

Target-state inputs: [T13 databases](13-encryption_levels.md), [T12 backups](12-disk_encryption.md), [T11 portal TLS](11-tls_audit.md), and [VPN audit](meddefense-crypto-audit-notes.txt). The Kali lab did not change production; the supplied folder has no T10 TLS deliverable.

## Part 1 — Technology Comparison

Costs are indicative USD service/device costs, not implementation quotes.

| Technology | What It Is | What It Protects | Typical Cost | Typical Deployment / MedDefense Fit |
|---|---|---|---|---|
| **TPM** | Device-bound cryptographic hardware/firmware; seals secrets to boot measurements. | Device keys and disk-unlock material. | Usually included: **$0 incremental hardware cost**; management extra. | BitLocker on employee laptops, with independent recovery escrow; not a central database key service. |
| **HSM** | Tamper-resistant hardware that stores keys and performs cryptographic operations. | Non-exportable wrapping/signing keys against extraction, not misuse by authorized callers. | Shared: **$1–2/active symmetric key version/month**, plus usage. AWS dedicated HA example: **$2,380.80/month**. | Shared cloud protection for MedDefense database/backup master keys. |
| **Secure enclave** | Hardware-isolated subsystem/processing environment; platform capabilities vary. | Device secrets and selected memory/computations, not automatically every application. | Included in supported devices: **$0 incremental hardware cost**; integration extra. | Use Apple's enclave on compatible physician iPads; verify models. Not NAS escrow. |
| **KMS (software)** | Central software service for access policy, versions, rotation, and audit. | Controlled key use/lifecycle; relies on its software execution boundary. | Google SOFTWARE example: **$0.06/active version/month + $0.03/10,000 symmetric operations**. | Central MedDefense key control; select hardware protection for critical keys. |

Sources: [Microsoft TPM](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-fundamentals), [Apple Secure Enclave](https://support.apple.com/en-ca/guide/security/sec59b0b31ff/web), [Google HSM architecture](https://docs.cloud.google.com/docs/security/cloud-hsm-architecture), [Google pricing](https://cloud.google.com/kms/pricing), and [AWS dedicated-HSM pricing example](https://aws.amazon.com/kms/pricing/).

## Part 2 — MedDefense Key Management Plan

**Architecture:** A **DEK** encrypts data; an HSM-held **KEK** wraps stored DEKs/unlock secrets. Hosts persist only wrapped material; authorized runtime memory still contains plaintext DEKs. HSM protection does not protect a mounted database from root.

Proposed projects: **`meddefense-keymgmt`** for databases and **`meddefense-backup-recovery`** for backups, with independent recovery IAM (**Finding 015 / RISK-007**). An external vault stores wrapped secrets and TLS/VPN credentials—not NAS-01 or plaintext configuration.

### Ownership and Access

Under the [1x03 RACI](../1x03_defense_blueprint/4-governance_architecture.md), **Sarah Park** administers keys; **James Chen** owns policy/incident accountability; **Clinical Operations** approves EHR access; the **Security Analyst** audits without decryption rights; the **CEO** approves funding/risk acceptance.

Separate administration from cryptographic use. Require MFA for people and scoped, short-lived service credentials—not permanent KMS tokens in configuration. **Sarah + James** approve escrow release/destruction through a controlled workflow; shared HSM does not automatically enforce that quorum.

### Key Lifecycle

Frequencies below are proposed policy targets, not observed settings.

| Key / System | Storage and Authorized Use | Rotation | If Compromised | If Lost |
|---|---|---|---|---|
| **Database — `ehr-db-01` / `ehr-srv-01`** | `db-kek` in HSM-backed KMS; wrapped unlock secret/optional record DEKs in the vault. Only database-unlock/EHR service identities use their respective keys; Sarah administers. | KEK annually; unlock secret every 90 days. Add/test a new LUKS slot, then remove the old; rewrap DEKs. Optional record DEKs annually. | Revoke identity access, isolate hosts, replace keys. An exposed DEK requires data re-encryption; changing a LUKS passphrase alone is insufficient. | Offline recovery slot, LUKS header backup, and protected record-DEK escrow under dual approval. Header alone cannot decrypt. |
| **Backups — `backup-srv-01`, NAS-01/offsite ciphertext** | `backup-kek` in the independent recovery project; wrapped set keys in catalog/vault. Only backup service/approved recovery operators unwrap—not NAS accounts. | New DEK per backup set; KEK annually. Keep old versions for retained backups. | Revoke access, replace keys, create clean backups; restrict old-key use to recovery. Stolen DEKs still expose old copies. | Independent offline/offsite key/catalog escrow. Test without production credentials; losing every usable key makes all replicas unrecoverable. |
| **Portal TLS — `web-srv-01`** | Private key in external vault; **0400 tmpfs** runtime file for TLS. Sarah/delegated web admin manages issuance. Root can still expose runtime keys. | New key at automated renewal before expiry; monitor and reload/test HTTPS (**Finding 013**). | Replace key/certificate, revoke old certificate through the CA, and investigate the host. | Generate a new key and reissue; no private-key escrow needed. Session keys are ephemeral. |
| **VPN — FortiGate/site peers** | Current authentication is undocumented. Target unique per-tunnel PSKs in protected endpoint configuration/vault; Sarah/delegated network admin manages them. Traffic keys stay in memory. | PSKs every 90 days, coordinated at both ends; target IKE 8-hour/IPsec 1-hour rekey after compatibility checks. | Replace PSKs on both peers, terminate old security associations, and remediate endpoints. | Restore protected PSK/configuration escrow or provision new credentials. Negotiate fresh traffic keys; do not escrow them. |

**Recovery controls:** Non-exportable HSM KEKs cannot be escrowed as plaintext. Use provider resilience plus the independent recovery paths above. Encrypt offline escrow, with unlocking material held separately under dual control. Cancel accidental deletion within the provider's recovery window; irreversible loss without recovery means data loss. Log to Wazuh and test all four recovery paths quarterly. Retain keys while dependent data exists.

## Part 3 — Is an HSM Justified?

[**RISK-002**](../1x03_defense_blueprint/10-risk_register.md#risk-002) and the [ALE workshop](../1x03_defense_blueprint/6-ale_workshop.md) model an EHR breach as:

- **SLE:** $9,075,000; **ARO:** 1/3; **inherent ALE:** **$3,025,000/year**.
- After the modeled access restriction: **residual ALE ≈ $1,210,000/year**.

Two initially active KEK versions—database and backups—cost **$24–48/year** at the task's $1–2/month assumption; Google shared HSM supports approximately $1/symmetric version/month. Add operations, retained rotation versions, vault hosting, integration, logging, support, and recovery work.

**[INFERENCE] Break-even:** `$48 / $1,210,000 × 100 ≈ 0.004%` reduction in residual EHR ALE covers base storage cost; substitute actual total annual cost for approval. The register has no key-specific probability or HSM effectiveness estimate: this is a threshold, **not measured ROI**. HSM protection does not fix unrestricted SQL access (**Finding 003**) or valid-identity abuse.

**Decision:** Approve **shared HSM-backed KMS**, subject to integration/recovery validation and total-cost approval; defer a dedicated cluster. AWS's published 31-day example annualizes to **$28,569.60** for hardware alone. The [1x03 strategy](../1x03_defense_blueprint/17-security_strategy.md) fully allocates **$120,000**, so James needs a CEO-approved additional/reallocated budget—not assumed spare funding. Retain segmentation, MFA, patching, and immutable backups.
