# Task 1 — CVE-2023-27997 Deep Dive

## Part 1 — NVD Research

**CVE:** CVE-2023-27997 (Fortinet PSIRT **FG-IR-23-097**; publicly nicknamed "XORtigate")
**Published:** 2023-06-13 | **Last modified:** 2026-07-31 | **Status:** Analyzed

**Full description:** A heap-based buffer overflow in FortiOS (7.2.4 and below, 7.0.11 and below, 6.4.12 and below, 6.0.16 and below) and FortiProxy (7.2.3 and below, 7.0.9 and below, 2.0.12 and below, 1.2.x, 1.1.x) SSL-VPN may allow a remote attacker to execute arbitrary code or commands via specifically crafted requests. The flaw is reachable **before authentication**, so it bypasses MFA entirely.

**CVSS v3.1:**
- Vector string: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Base score: **9.8 CRITICAL** (both the NVD primary metric and the Fortinet secondary metric agree)
- Exploitability sub-score 3.9; Impact sub-score 5.9
- Note: the CISA advisory quotes **9.2**. That figure reflects Fortinet's original June 2023 scoring; NVD's current analyzed record is 9.8. The difference does not change the response — both are Critical.
- CISA SSVC decision points: exploitation **active**, automatable **yes**, technical impact **total**.

**CWE classification:**
- NVD primary: **CWE-787** — Out-of-bounds Write
- Fortinet: **CWE-122** — Heap-based Buffer Overflow

**Affected products and versions:**

| Product | Affected ranges | Fixed from |
|---|---|---|
| FortiOS | 7.2.0–7.2.4 | 7.2.5 |
| FortiOS | 7.0.0–7.0.11 | 7.0.12 |
| FortiOS | 6.4.0–6.4.12 | 6.4.13 |
| FortiOS | 6.2.0–6.2.13 | 6.2.14 |
| FortiOS | 6.0.0–6.0.16 | 6.0.17 |
| FortiProxy | 7.2.0–7.2.3, 7.0.0–7.0.9, 2.0.0–2.0.12, 1.2.0–1.2.13, 1.1.0–1.1.6 | vendor upgrade path |

MedDefense relevance: `AST-043` is a **FortiGate 100F**, which runs FortiOS. The installed version is undocumented, so it cannot yet be excluded from these ranges.

**References:**
- Fortinet PSIRT advisory: `https://fortiguard.com/psirt/FG-IR-23-097` (vendor advisory and patched firmware)
- CISA KEV entry: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-27997`
- NVD record: `https://nvd.nist.gov/vuln/detail/CVE-2023-27997`

## Part 2 — Exploit Assessment

**Is there a public exploit?** Yes, but not in the two databases used by the 1x02 methodology:
- `searchsploit fortigate` / `searchsploit fortios` returned 18 unique historical Fortinet entries; the newest are EDB-52239 (FortiOS/FortiProxy/FortiSwitchManager authentication bypass, CVE-2022-40684) and EDB-52336 (FortiOS SSL-VPN insufficient session expiration, CVE-2024-50562). **Neither maps to CVE-2023-27997.**
- `searchsploit --cve 2023-27997` returned **no results** in Exploit-DB.
- There is **no merged Metasploit module** — only an open module request (rapid7 issue #18163).
- However, public proof-of-concept code does exist outside Exploit-DB, and the Lexfo "xortigate" research demonstrates the heap-overflow primitive. Exploit-DB absence therefore understates real-world attacker capability.

**Is this CVE in the CISA KEV catalog?** **Yes.** Added **2023-06-13**, federal remediation due **2023-07-04**. KEV presence is confirmation that the vulnerability has been exploited in the wild, not merely that exploitation is theoretically possible.

**Exploitability Score (1x02 Task 4 scale): 5.**

| Criterion | Evidence | Score contribution |
|---|---|---|
| In CISA KEV | Yes, added 2023-06-13 | 5 |
| Actively exploited | SSVC exploitation = active; used as the initial access vector in all 5 Crimson Tide incidents | 5 |
| Public tooling | Public PoCs exist; no Exploit-DB or Metasploit module | partial |
| Ease | Pre-authentication, network-reachable, low complexity, no user interaction, automatable | 5 |

The only factor that pulls below a pure 5 is the absence of a Metasploit module. That is outweighed by KEV listing, confirmed in-the-wild use against hospitals matching MedDefense's profile, and the pre-authentication nature of the bug. **Treat as score 5 — weaponized and actively exploited.**

**What this means for urgency:** the advisory states that in **4 of 5** incidents the FortiGate firmware was at least 6 months behind, and in 2 cases more than 18 months behind. A public, pre-authentication, KEV-listed exploit against a device whose version MedDefense cannot currently verify is the highest-priority patch in the environment — ahead of every finding in the 1x02 register, because it is the door rather than a room.

## Part 3 — MedDefense CVSS Contextualization

NIST CVSS v3.1 environmental metrics applied to `AST-043`:

| Metric | Value | MedDefense justification |
|---|---|---|
| MAV (Modified Attack Vector) | Network | SSL-VPN portal is Internet-facing. |
| MAC (Modified Attack Complexity) | Low | Exploitation requires no special conditions and is automatable. |
| MPR (Modified Privileges Required) | None | Pre-authentication; MFA is irrelevant to this phase. |
| MUI (Modified User Interaction) | None | Appliance is attacked directly. |
| **MS (Modified Scope)** | **Changed** | The vulnerable component is a **security-enforcing device**: compromising the FortiGate gives control over the access decisions protecting EHR, AD, billing, PACS and backups. This is exactly what CVSS scope-change represents, and it is the key MedDefense modifier. |
| MCR / MIR / MAR | High / High / High | Total loss of confidentiality, integrity and availability across the protected environment. |
| E (Exploit Maturity) | High (functional/weaponized code) | Public PoCs plus KEV plus active hospital targeting. |
| RL (Remediation Level) | Official Fix | A vendor patch has existed since June 2023. |
| RC (Report Confidence) | Confirmed | Vendor advisory, NVD analysis, CISA KEV. |

**Result:**

| Metric set | Score |
|---|---|
| Base (production environment, scope unchanged) | **9.8 Critical** |
| Environmental (MS:Changed, CR/IR/AR:High) | **10.0 Critical** |

**Is the adjusted score higher or lower?** **Higher — 10.0 versus 9.8.**

The increase is small numerically because 9.8 is already near the ceiling, but the reason for it matters more than the number. The Base score treats the FortiGate as a standalone system whose compromise affects only itself. The Environmental score reflects that the FortiGate is MedDefense's **single** perimeter control with no redundancy, terminates all three site-to-site tunnels, sits on Kill Chain #1, #2 and #3, and has a **lapsed support contract** so that the "Official Fix" is not currently obtainable. Those are exactly the conditions CVSS Environmental metrics exist to capture. Three points to be explicit about:

1. The `RL:Official Fix` value makes the *scored* impact look smaller than MedDefense's *operational* position, because the contract expiry means the fix cannot be downloaded. Treat 10.0 as a floor, not a ceiling.
2. The 1x04 OSINT review found the same device potentially affected by CVE-2024-55591 (authentication bypass, CVSS 9.8). Two independent pre-authentication paths to the same device mean the device's own risk is higher than either CVE scored in isolation.
3. If the installed FortiOS version turns out to be outside the affected ranges, the Environmental score for this specific CVE drops to zero applicability — which is why version verification is the first action in the 72-hour plan, not the patch itself.
