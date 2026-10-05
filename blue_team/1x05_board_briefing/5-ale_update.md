# Task 5 — ALE Update: Crimson Tide

## Part 1 — Original vs Updated ALE

### Original (1x03 Task 6, validated in Task 10)

| Component | Value | Derivation |
|---|---|---|
| Asset Value (AV) | $9,548,000 | Billing ransomware exposure $473,000 + EHR breach exposure $9,075,000 |
| Exposure Factor (EF) | 1.00 | Modeled event is a successful full ransomware-plus-exfiltration campaign |
| **SLE** | **$9,548,000** | AV × EF |
| **Original ARO** | **0.30** | Sector baseline ≈ 1 event every 3–4 years; 1 ÷ 0.30 = 3.33 years |
| **Original ALE** | **$2,864,400/yr** | $9,548,000 × 0.30 |

### New intelligence

- **5** confirmed compromises of comparable hospitals (100–500 beds) in **10 days**
- **3** of those in MedDefense's geographic region
- A consistent chain: FortiGate CVE-2023-27997 initial access, a flat network in all 5 cases, backups on the production network in all 5, unencrypted databases in 4 of 5, Kerberoasting in 3 of 5

### Does the SLE change? No — reviewed and kept

The template asks for *New SLE × New ARO*, so the loss side was re-checked against the advisory's victim data rather than assumed:

| SLE component (1x03) | 1x03 value | Advisory evidence | Decision |
|---|---|---|---|
| Billing downtime | 18 days × $16,000 = $288,000 | Victims were down 11–14 days (one still on paper in week 2) | Keep — 1x03 already assumes a **longer** outage |
| EHR breach | 50,000 records × $165 + notification + litigation + reputation = $9,075,000 | Exfiltration of 15–65 GB of patient, financial and HR data before encryption in all 5 | Keep — already models full-population disclosure |
| Ransom payment | Not included | Demands $1.2M–$3.5M; 2 of 5 paid | **Assumption:** MedDefense does not pay. If it did, SLE would rise to roughly **$10.6M–$13.0M** |

**New SLE = $9,548,000 (unchanged).** The advisory changes how often the loss is expected, not how large it is.

A 10-day burst cannot be extrapolated across a year. Three of five victims were hit in MedDefense's own region within 10 days; if that intensity were sustained for 12 months it would imply multiple attacks per hospital per year, which is not credible. The defensible method is a **hazard model over a bounded elevated window**, reverting to the sector baseline afterwards.

**Assumption (stated explicitly):** the region contains **25** hospitals of comparable profile (100–500 beds). This is an estimate; sensitivity is shown below.

**Elevated window:** **30 days**, on the reasoning that an emergency CISA/FBI advisory of this severity typically triggers sector-wide patching and heightened monitoring that suppresses the campaign within weeks. This is an assumption, not a fact from the advisory.

### Calculation

Daily hazard rate per comparable hospital during the campaign:

**h = 3 ÷ (25 hospitals × 10 days) = 0.012 per hospital-day**

Probability of at least one event inside the 30-day elevated window:

**P(elevated) = 1 − e^(−0.012 × 30) = 1 − e^(−0.36) = 0.302**

Probability of at least one event in the remaining 335 days at the original sector baseline:

**P(baseline) = 1 − e^(−0.30 × 335 ÷ 365) = 1 − e^(−0.2753) = 0.241**

Combine as independent periods:

**Updated ARO = 1 − (1 − 0.302)(1 − 0.241) = 1 − 0.698 × 0.759 = 0.470**

**Updated ALE = $9,548,000 × 0.470 = $4,487,560 per year**

### What changed and why

| | Original | Updated | Change |
|---|---:|---:|---:|
| ARO | 0.30 | **0.470** | **+57%** |
| SLE | $9,548,000 | $9,548,000 | unchanged |
| **ALE** | **$2,864,400** | **$4,487,560** | **+$1,623,160** |

The loss magnitude did not change — a full campaign still costs about $9.5M. What changed is **how often we expect it**. The original ARO came from historical sector frequency; the advisory supplies live, regional, same-profile victim data showing an active campaign, so the near-term hazard is materially higher than the historical average. That is the entire point of continuous risk analysis: new intelligence, new numbers.

### Sensitivity to the population assumption

| Comparable regional hospitals | 30-day hazard probability | Updated ARO | Updated ALE |
|---:|---:|---:|---:|
| 15 | 0.451 | 0.583 | $5,569,164 |
| **25 (used)** | **0.302** | **0.470** | **$4,487,560** |
| 40 | 0.201 | 0.394 | $3,758,828 |

Even under the most favourable assumption tested (40 comparable hospitals), the ALE rises to **$3.76M** — still a 31% increase over the original. The conclusion is not sensitive to the assumption.

---

## Part 2 — Budget Impact

### Does the updated ALE change any 1x03 Task 7 conclusion?

Every control whose value derives from enterprise-ransomware ARO scales by **0.470 ÷ 0.30 = 1.567×**.

| Control | Task 7 net value | **Updated net value** | Verdict change |
|---|---:|---:|---|
| Network segmentation | $1,683,640 | **$2,657,536** | Justified → Justified (stronger) |
| MFA — VPN/admin | $1,422,200 | **$2,233,780** | Justified → Justified (stronger) |
| Wazuh SIEM | $981,540 | **$1,549,646** | Justified → Justified (stronger) |
| EDR upgrade | $833,320 | **$1,320,268** | Justified → Justified (stronger) |
| Westside firewall | $123,220 | **$204,378** | Justified → Justified (stronger) |
| Offsite immutable backup | $66,600 | $66,600 | Unchanged basis (billing-recovery proxy, not ransomware ARO) |
| 24/7 outsourced SOC | $58,535 | **$169,316** | **Marginal → Justified in value (still unaffordable)** |
| Full medical-device isolation | −$35,500 | **−$35,500** | **Not Justified → Not Justified** |

**Controls previously "Not Justified" now justified?** **No.** The only control formally rated *Not Justified as Proposed* was the $95,000 full medical-device isolation/monitoring architecture. Its ALE reduction ($59,500) is driven by medical-device frequency and patient-safety loss, **not** by ransomware ARO, so the Crimson Tide data does not change it: net value remains **−$35,500**. The recommendation stands — fund the ~$27,000 targeted Alaris/Philips work instead.

**The one meaningful shift** is the 24/7 outsourced SOC: it moves from *Marginal* ($58,535) to clearly positive ($169,316). But its annual cost of **$136,960 still exceeds the entire $120,000 budget**, so the affordability conclusion from Task 7 is unchanged even though the value case is now unambiguous. Revisit it once SIEM and EDR telemetry produce real alert volumes.

### ROI of the $2,400 FortiGate support renewal

The renewal is not a control by itself — it is the prerequisite that makes the patched firmware obtainable. Score it against the risk it removes.

**Break-even effectiveness:**

**$2,400 ÷ $4,487,560 = 0.0535%**

The renewal pays for itself if it reduces expected annual campaign loss by more than **five hundredths of one percent**. Patching removes the initial-access vector used in all five Crimson Tide incidents. **Assumption:** removing that vector eliminates far more than 0.05% of the exposure — the illustrations below test deliberately small effectiveness values to show the conclusion does not depend on that judgement.

A deliberately conservative illustration: assume the patch prevents only **1%** of the expected loss.

**Avoided loss = 1% × $4,487,560 = $44,876**

**ROI = ($44,876 − $2,400) ÷ $2,400 ≈ 17.7×**

At a 10% effectiveness assumption the avoided loss is $448,756 and the ROI is roughly 186×. On any defensible effectiveness assumption between 1% and 100%, the $2,400 renewal is the highest-return spending decision in the entire program — it is a rounding error against a $4.49M annualized exposure.

### Should the Board approve emergency spending beyond the $120,000?

**Yes, but bounded and, where possible, reallocated rather than added.**

Three observations frame the decision:

1. **The $2,400 is not really a budget question.** Approve it immediately and separately — its break-even is 0.05% and delay is itself the risk. It is the only Tier 2 item that is genuinely blocking.

2. **The 1x03 alternative allocation already freed $20,000.** 1x03 Task 8 showed that deferring the Westside enterprise firewall releases $20,000 while retaining the five highest-value controls. That is the cleanest funding source: **reallocate $20,000, spend $2,400 on the renewal, and hold the remainder for emergency professional services.**

3. **If the Board wants to keep the Westside firewall in Year 1, approve a bounded supplemental rather than an open-ended one.** An emergency authorization of **$25,000** is justified on the same break-even logic: it is justified as long as it reduces expected loss by more than $25,000 ÷ $4,487,560 = **0.56%** — a threshold an active, regionally confirmed ransomware campaign against MedDefense's exact profile clears by a wide margin.

**Recommendation to the Board:**

| Decision | Amount | Rationale |
|---|---:|---|
| Immediate authorization — FortiGate support renewal | **$2,400** | Break-even 0.0535%; unblocks the only patch path |
| Emergency supplemental — vendor-assisted FortiGate remediation and segmentation acceleration | **up to $25,000** | Justified if it reduces expected loss by >0.56% |
| Funding source | Reallocate **$20,000** freed by deferring the Westside firewall; supplement only the remainder | Preserves the strategy's core investment priority without inflating the ceiling |
| Do **not** fund now | $136,960 24/7 SOC | Value now clear, but affordability unchanged |
| Do **not** fund | $95,000 full medical-device architecture | Still net-negative; fund the $27,000 targeted work instead |

**Bottom line:** the updated ALE does not overturn the 1x03 portfolio — it strengthens it and re-ranks urgency. The controls MedDefense already selected become roughly 1.57× more valuable overnight, which means the correct response to Crimson Tide is not a new strategy but **faster execution of the existing one**, starting with $2,400 that removes the front door.
