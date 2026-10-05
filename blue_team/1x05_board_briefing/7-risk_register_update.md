# Task 7 — Risk Register Update: Crimson Tide

Register last approved **2026-09-21**, next scheduled review 2026-10-21. This update is performed **out of cycle** on 2026-10-05 in response to CISA AA26-077A.

---

## Part 1 — Update to Existing Entry: RISK-001

| Field | Previous value | **Updated value** |
|---|---|---|
| **Risk ID** | RISK-001 | RISK-001 (unchanged) |
| **Risk Description** | A ransomware operator gains an internal foothold and uses MedDefense's flat network, weak identity boundaries, limited monitoring, and reachable backups to create an enterprise-wide ransomware and data-extortion incident. | Now specifies the campaign: a **Crimson Tide** affiliate exploits the Internet-facing FortiGate SSL-VPN, harvests VPN credentials, moves across the flat network, exfiltrates EHR/billing/HR data, destroys reachable backups, and deploys a modified BlackSuit payload by GPO. |
| **Risk Category** | Operational | Operational (unchanged) |
| **Threat Source** | TA-1 Ransomware Groups / Organized Crime | **Crimson Tide (CT)** — RaaS affiliate network using a modified BlackSuit variant; double extortion; 100–500-bed regional hospitals; 4–7 day dwell time; 96-hour payment deadline. |
| **Vulnerability** | Findings 003, 007, 015; additional exposure from 004 and 016 | **New CVE-2023-27997 (FortiGate, Phase 1)** joins Findings 003, 004, 007, 015 and 016. The FortiGate is now the entry point, not merely one of several exposures. |
| **Affected Asset(s)** | AST-043 FortiGate 100F; AST-005/006 AD; AST-001/002 EHR; AST-009/010 backup infrastructure; broader internal network | Unchanged — but AST-043 is upgraded in practice from "affected" to **primary entry vector**. |
| **Likelihood** | **3 — Possible**; ARO **0.30** | **4 — Likely**; **updated ARO 0.470** (see Task 5). Justification: an active campaign with three confirmed victims in MedDefense's own region, against an environment exhibiting all four of the advisory's enabling conditions. Recurrence interval falls from 3.33 years to **≈ 2.1 years**. |
| **Impact** | 5 — Severe/Catastrophic | 5 — Severe/Catastrophic (unchanged). The advisory confirms patient/financial exfiltration, 11–14 day downtime and seven-figure demands ($1.2M–$3.5M) at comparable hospitals. |
| **Inherent Risk Score** | 3 × 5 = **15** | **4 × 5 = 20** |
| **ALE** | $9,548,000 × 0.30 = **$2,864,400/yr** | $9,548,000 × 0.470 = **$4,487,560/yr** (+$1,623,160, +57%) |
| **Risk Owner** | James Chen, Deputy CISO | Unchanged |
| **Treatment Decision** | Mitigate | **Mitigate — still holds.** The increase strengthens rather than changes the decision. |
| **Treatment Justification** | The risk is too large to accept because one successful foothold can propagate across multiple Critical systems and recovery infrastructure. | **Still valid and now higher priority.** The advisory demonstrates that this exact propagation path has succeeded at five comparable hospitals in ten days. The updated ALE of $4.49M makes mitigation more clearly correct than at the original $2.86M. |
| **Planned Control(s)** | Network segmentation; MFA on VPN and administrative accounts; Wazuh SIEM; EDR upgrade; offsite immutable backup replication. | Unchanged set, **re-sequenced**: (1) FortiGate patch via renewed support contract, (2) restrict/disable SSL-VPN until patched, (3) NAS-01 isolation **tonight**, (4) AD Kerberos hardening, (5) segmentation, (6) SIEM/EDR. |
| **Residual Risk** | Medium-High — 2 × 4 = 8; segmentation-only model $1,145,760/yr | Medium-High — **2 × 4 = 8**, but the residual figure must be restated on the new ARO: $9,548,000 × 0.40 × 0.470 = **$1,795,024/yr** after segmentation alone. Layered controls (patch, MFA, SIEM, EDR) reduce this further and are not added together to avoid double-counting. |
| **KRI** | Any unauthorized cross-zone path to EHR, AD, or backup infrastructure; confirmed ransomware execution; backup administration reachable from a normal user segment; privileged remote access without MFA. | **New, Crimson Tide-specific:** match on any advisory IOC (payload hash `a3f7d8e9…`, modified Rclone hash `b4e8f9a0…`); outbound transfer >5 GB to cloud storage; `vssadmin delete shadows` on any host; new GPO created outside a change window; Rclone appearing on a host where it was not previously present; unusual FortiGate CLI commands; unexpected VPN sessions or admin accounts; **FortiOS version reported outside a currently supported patched release**. |
| **Review Date** | 2026-10-21 | **2026-10-05 (immediate)** — out-of-cycle review; next scheduled review remains 2026-10-21. |

---

## Part 2 — New Entry: RISK-NEW-001

**Risk ID:** RISK-NEW-001

**Risk Description:** An unauthenticated external attacker exploits the SSL-VPN heap overflow in CVE-2023-27997 to execute code on MedDefense's single FortiGate 100F, gaining full control of the perimeter firewall and every VPN tunnel, then using that position to reach the flat internal network.

**Risk Category:** Operational

**Threat Source:** Crimson Tide (CT) RaaS affiliate network; also exploitable by any opportunistic actor with the public PoC, and by Nation-State APTs.

**Vulnerability:** **CVE-2023-27997** — heap-based buffer overflow (CWE-122 / CWE-787) in FortiOS SSL-VPN; CVSS v3.1 base **9.8 Critical**; CISA KEV listed (added 2023-06-13). Not a 1x02 scanner finding — the FortiGate was never a responsive scan host. Related OSINT finding: CVE-2024-55591 (authentication bypass, CVSS 9.8) from 1x04 Task 9.

**Affected Asset(s):** **AST-043 FortiGate 100F** — MedDefense's only firewall and the VPN termination point for Central, Westside and Corporate HQ. Downstream: every asset behind it.

**Likelihood:** **4 — Likely.** The advisory records use of this exact vector in all five incidents; a public exploit exists; and 4 of 5 victims were running firmware at least 6 months out of date. **Assumption:** the FortiOS version is undocumented, so the device is treated as affected until verified (consistent with Task 0). If verification shows a patched release, likelihood drops to **2 — Unlikely** and this entry is re-scored.

**Impact:** **5 — Severe/Catastrophic.** There is no redundant perimeter device. Compromise yields control of all three site-to-site tunnels and the security policy protecting EHR, AD, billing, PACS and backups.

**Inherent Risk Score:** **4 × 5 = 20**

**ALE:** **$4,487,560/year** — computed as ARO 0.470 × SLE $9,548,000. This is an upper bound until the firmware version is verified.

> **Non-additivity warning (important):** RISK-NEW-001 is a *view of the same loss scenario* as RISK-001, seen through a specific vulnerability rather than a general foothold. It must **not** be summed with RISK-001, RISK-003, RISK-007 or RISK-010. The register already treats those enabling-stage risks this way. RISK-NEW-001 exists so the FortiGate vulnerability has its own owner, KRI, treatment and review trail.

**Risk Owner:** Sarah Park, IT Director (technical custodian and executor); James Chen, Deputy CISO (accountability and escalation).

**Treatment Decision:** **Mitigate — patch and restrict.**

**Treatment Justification and cost-justification against the ALE:**

Two cost inputs are in scope: the **$2,400** support contract renewal (a prerequisite to obtaining firmware) and the internal labour to apply it.

**Break-even test:**
- Break-even effectiveness = $2,400 ÷ $4,487,560 = **0.0535%**
- The renewal is financially justified if it reduces expected annual loss by more than **0.05%**.

**Conservative illustration:** even if patching removed only **1%** of the expected loss, the avoided loss is **$44,876** — an **ROI of ≈ 17.7×**. At 10% effectiveness the avoided loss is $448,756.

**Modeled test (patch plus SSL-VPN restriction):** **assumption** — removing the documented initial-access vector returns the campaign ARO from 0.470 to 0.20 (residual paths: phishing, Westside, valid credentials):

**ALE after control = $9,548,000 × 0.20 = $1,909,600/yr**
**Risk reduction = $4,487,560 − $1,909,600 = $2,577,960/yr**
**Net benefit = $2,577,960 − $2,400 = $2,575,560 in Year 1**

**Verdict: strongly justified.** No credible effectiveness assumption produces a negative return. The decision is not marginal — this is the single highest-return $2,400 in the program.

**Planned Control(s):**
1. Renew the FortiGate support contract ($2,400) — emergency Board authorization.
2. Patch FortiOS to a fixed release (7.2.5+ / 7.0.12+ / 6.4.13+ as applicable) via the vendor-supported upgrade path.
3. Until patched, disable external SSL-VPN access (IPSec site-to-site tunnels remain up).
4. Enforce MFA on all VPN and administrative access.
5. Restrict FortiGate management to a dedicated management source rather than the general network.
6. Add firmware-version and IOC monitoring to the Wazuh detection content.

**Residual Risk:** **Medium-High — 2 × 5 = 10.** Patching removes the documented initial-access vector but not phishing, the Westside consumer perimeter (RISK-010), or valid-credential abuse. Residual ALE modeled at **$1,909,600/yr** (ARO 0.20).

**KRI:** Installed FortiOS version outdated relative to the vendor's supported releases; SSL-VPN reachable from the Internet without MFA; firmware integrity not verified against the vendor hash before installation; any advisory IOC match in FortiGate logs; unexpected administrator or local accounts; unexpected VPN sessions; configuration drift on the management-access rule.

**Review Date:** **2026-10-05** (immediate); then monthly.

---

## Part 3 — Register Governance Test

The governance note in the 1x03 Risk Register defines out-of-cycle review triggers as follows:

> "An out-of-cycle review is triggered by a material incident, **a new Critical vulnerability affecting a MedDefense asset, a significant change in threat intelligence**, deployment failure of a planned control, a major architecture/vendor change, or evidence that an ALE or risk assumption is no longer valid."

**Does the Crimson Tide advisory qualify? Yes — it independently satisfies three of the six stated triggers, and arguably a fourth.**

| Trigger criterion | Does it apply? | Evidence |
|---|---|---|
| A material incident | Not yet | No confirmed MedDefense compromise; three regional victims are comparable organizations, not MedDefense itself. |
| **A new Critical vulnerability affecting a MedDefense asset** | **Yes** | CVE-2023-27997 is CVSS 9.8, CISA KEV-listed, and affects **AST-043**, MedDefense's only perimeter firewall. The vulnerability was not in the 1x02 register because the FortiGate was never fingerprinted by the scan. |
| **A significant change in threat intelligence** | **Yes** | A CRITICAL-severity CISA/FBI/HHS emergency advisory describing an active campaign with **5 victims in 10 days, 3 in MedDefense's region**, using a consistent chain that maps to MedDefense's environment phase by phase (Task 0). This is precisely a significant change in threat intelligence. |
| Deployment failure of a planned control | Partially | The 1x03 segmentation, MFA, SIEM and backup controls were designed but **not yet deployed** — and the advisory names each of those absences as an enabling condition. This is a delivery slippage rather than a control failure, so it is noted but not claimed as the qualifying trigger. |
| Major architecture/vendor change | No | No architecture or vendor change has occurred. |
| **Evidence that an ALE or risk assumption is no longer valid** | **Yes** | The original RISK-001 ARO of 0.30 came from historical sector frequency (1 event per 3–4 years). Live data showing three regional hospital compromises in ten days invalidates that assumption as a description of the *current* hazard. Task 5 recalculates ARO to 0.470 (+57%). |

**Determination:** the advisory **does** qualify as an out-of-cycle review trigger. The register is therefore reviewed immediately rather than waiting for the scheduled 2026-10-21 cadence.

**Governance actions required by the register's own process:**

1. The **Security Analyst** records the trigger, attaches the advisory and the Task 0/Task 1 analysis as supporting evidence, and updates RISK-001 and RISK-NEW-001.
2. The trigger is **escalated immediately to James Chen** as the accountable owner, and to Sarah Park as the Risk Owner for RISK-NEW-001.
3. Sarah Park must define corrective action or formally request risk acceptance. The corrective action is the Tier 1/Tier 2 plan in Task 3.
4. Any material residual risk requiring acceptance is escalated to the **CEO** — Security and IT cannot accept it unilaterally. Specifically, if the Board declines the $2,400 renewal and MedDefense continues to run an unverified, potentially vulnerable FortiGate, that acceptance must be recorded at CEO level with the **full $4,487,560/yr exposure** documented (the $1,909,600 residual applies only after patching).
5. The next scheduled review remains **2026-10-21**, but the Crimson Tide entry stays under daily review until the FortiGate firmware is verified and patched.
