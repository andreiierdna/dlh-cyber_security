# Task 0 — Crimson Tide: MedDefense Impact Assessment

Advisory: CISA AA26-077A, TLP:WHITE, severity CRITICAL, received 4 hours ago. Assessment time-budget: board presentation 09:00 tomorrow.

## Assumptions and evidence limits

- MedDefense's FortiOS version is **not documented**; the 1x04 OSINT review could not fingerprint the device. Exposure is therefore assessed as "unknown but not disproven".
- The advisory names the affected ranges (FortiOS 7.2.0–7.2.4 and 7.0.0–7.0.11). It does not state MedDefense's version, so Phase 1 is treated as exposed until verified.
- No MedDefense log review for Crimson Tide IOCs has been performed yet; absence of evidence is not evidence of absence.
- The advisory's CVSS figure for CVE-2023-27997 is 9.2; NVD's current record is 9.8. Both are Critical; the difference is documented in Task 1.
- CVE-2023-27997 was not identified in the 1x02 vulnerability scan because the FortiGate was never a responsive scan host; this is an OSINT/new-CVE mapping, not a scanner finding.

## Phase-by-phase mapping

### Phase 1 — Initial Access
- **Advisory Description:** The attacker sends a crafted request to the FortiOS SSL-VPN portal and executes code on the FortiGate itself, pre-authentication.
- **Target System:** `AST-043` FortiGate 100F — MedDefense's only firewall and the VPN termination point for Central, Westside and HQ.
- **Vulnerability Reference:** New CVE — **CVE-2023-27997** (advisory); related OSINT finding **CVE-2024-55591** from 1x04 Task 9.
- **Gap Reference:** GAP-003 (network core exposed to unauthorized administrative control); GAP-011 (no enterprise vulnerability/patch management).
- **Crypto Weakness:** None required for this phase; SSL-VPN is reachable pre-authentication, so MFA does not apply (see Task 1).
- **Current Protection:** C-001 default-deny firewall policy, C-002 inbound restriction to HTTP/HTTPS, C-027 site-to-site VPN. None of these block a request to the SSL-VPN service itself.
- **Verdict:** **EXPOSED**

### Phase 2 — Internal Reconnaissance
- **Advisory Description:** From the appliance, the attacker harvests VPN credentials from memory and dumps the routing table to map internal subnets.
- **Target System:** FortiGate credential store, then `AST-005/006 ad-dc-01/ad-dc-02` and Fortinet VPN service accounts.
- **Vulnerability Reference:** Findings 007 (LDAP signing) and 018 (weak Kerberos types); undocumented VPN service-account privileges.
- **Gap Reference:** GAP-003; GAP-007 (AD relies on passwords without mandatory MFA).
- **Crypto Weakness:** CRYPTO-010 (MD4 NT hashes), CRYPTO-011 (RC4/DES Kerberos still enabled).
- **Current Protection:** C-005 key-only SSH on `ehr-srv-01` only; C-009 password policy; no egress filtering that would detect routing-table dumps.
- **Verdict:** **EXPOSED**

### Phase 3 — Lateral Movement
- **Advisory Description:** Using harvested credentials, the attacker RDPs to Windows hosts, SSHes to Linux hosts and uses WMI for remote execution across a flat network.
- **Target System:** Flat `10.10.0.0/16` — including `ehr-srv-01`, `billing-srv-01`, `pacs-srv-01`, `file-srv-01` and approximately 320 Central endpoints.
- **Vulnerability Reference:** Finding 009 (password-based SSH, no lockout), Finding 019 (RDP enabled on five systems), Finding 018 (Kerberoasting).
- **Gap Reference:** GAP-003 (no meaningful segmentation); GAP-007; GAP-013 (no automated offboarding).
- **Crypto Weakness:** CRYPTO-011 — RC4 service tickets are crackable offline; MD4 NT hashes are exposed to credential dumping.
- **Current Protection:** C-009 password policy and C-010 five-attempt lockout exist, but the advisory's observed Kerberoasting path is offline and bypasses lockout entirely.
- **Verdict:** **EXPOSED**

### Phase 4 — Data Exfiltration
- **Advisory Description:** The attacker copies raw database files with Rclone to attacker-controlled cloud storage — no database credentials required.
- **Target System:** `ehr-db-01` (EHR), `billing-srv-01` (billing), HR/file data on `file-srv-01`.
- **Vulnerability Reference:** Finding 003 (PostgreSQL reachable from `/16`), Finding 006 (MySQL bound to `0.0.0.0`), Finding 023 (USB unrestricted).
- **Gap Reference:** GAP-006 (EHR reachable beyond need), GAP-014 (no DLP or egress control).
- **Crypto Weakness:** CRYPTO-001/004 — **no at-rest encryption** on either database volume, so raw files are readable exactly as the advisory describes; CRYPTO-005 — plaintext MySQL transport.
- **Current Protection:** None effective. C-004 logs firewall traffic but the logs are local and unmonitored (C-018 rated Weak), and outbound policy is permissive (documented in GAP-008).
- **Verdict:** **EXPOSED**

### Phase 5 — Backup Destruction
- **Advisory Description:** Before encrypting, the attacker targets backup infrastructure — NAS/SAN on the same network, shadow copies, and backup catalogs.
- **Target System:** `AST-010 NAS-01` (DSM on TCP/5000/5001) and `AST-009 backup-srv-01` (Veeam).
- **Vulnerability Reference:** Finding 015 (DSM management reachable from the whole internal network; backups unencrypted).
- **Gap Reference:** GAP-004 (production and backup copies share one failure domain); GAP-018 (no change management on backup jobs).
- **Crypto Weakness:** CRYPTO-013/014 — NAS-01 stores plaintext backup sets; the supported AES-256-CBC shared-folder feature is disabled and would share the NAS key store anyway.
- **Current Protection:** C-012 nightly Veeam job and C-019 RAID-5 provide **availability**, not isolation. Both are inside the same room, rack and network as production.
- **Verdict:** **EXPOSED**

### Phase 6 — Ransomware Deployment
- **Advisory Description:** A modified BlackSuit payload is pushed by GPO from a compromised Domain Controller to Windows systems, with Linux hosts encrypted separately over SSH.
- **Target System:** `ad-dc-01` as the GPO source; servers `ehr-srv-01`, `billing-srv-01`, `file-srv-01`, `pacs-srv-01`; approximately 320 Central and 45 Westside endpoints.
- **Vulnerability Reference:** Finding 007 (unsigned LDAP), Finding 018 (weak Kerberos), Finding 011 (unsupported Ubuntu 18.04 on `billing-srv-01`).
- **Gap Reference:** GAP-007 (AD without MFA); GAP-008 (no server-class malware protection); GAP-016 (no centralized detection).
- **Crypto Weakness:** None blocking — the payload uses its own AES-256-CBC with RSA-2048 key wrapping. Weak MedDefense cryptography does not stop this phase; it only made Phase 4 easier.
- **Current Protection:** **Partial.** C-011 Sophos covers 372 managed Windows endpoints and has demonstrated real detections, and C-010 lockout limits password guessing. However Sophos explicitly excludes servers, 15 agents are inactive, and EDR is not deployed — so server-side execution and GPO deployment are largely undetected.
- **Verdict:** **PARTIALLY PROTECTED**

### Phase 7 — Extortion
- **Advisory Description:** Double extortion — a decryption ransom plus a threat to publish exfiltrated patient data, with a 96-hour deadline and direct contact to executives.
- **Target System:** Executive leadership (CEO/CFO), communications, legal, and the clinical operations chain.
- **Vulnerability Reference:** Not a technical finding — enabled by the exfiltration in Phase 4.
- **Gap Reference:** GAP-012 (no formal enterprise incident response and recovery process); GAP-014 (no DLP, so the disclosure cannot be scoped confidently).
- **Crypto Weakness:** None; the leverage is stolen plaintext data, which CRYPTO-001/004 did not protect.
- **Current Protection:** C-016 awareness training (uneven: 94% HQ, 71% Central, 58% Westside) is the only relevant control. There is no IR plan, no tested disaster recovery, no communications procedure and no retainer for external response.
- **Verdict:** **EXPOSED**

## Overall Exposure Score

**6 / 7 phases EXPOSED.** Phase 6 is rated PARTIALLY PROTECTED on the strength of C-011 Sophos coverage on managed endpoints, which the advisory's IOCs (known payload hash, `vssadmin delete shadows`, Rclone) could plausibly trigger at the endpoint layer. Every other phase has no control that materially interrupts the attacker's described action.

## Critical Finding

**Verify the FortiOS version on the FortiGate within the next 4 hours and, if it falls in the affected range, disable external SSL-VPN access or patch it immediately — because MedDefense matches every one of the four enabling conditions in the advisory (unpatched FortiGate, flat network, RC4-enabled Kerberos, unencrypted reachable backups) and Regional Hospital C is 45 miles away.**
