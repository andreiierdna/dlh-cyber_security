# MedDefense Health Systems  
## Task 8 — The Budget Game

### Decision Rule

MedDefense has a fixed annual security budget of:

**Budget = $120,000**

The Task 7 controls are evaluated using:

**Net Value = ALE Reduction − Annual Control Cost**

For selection purposes, the Task 7 ALE reductions are used as the common scoring basis. Because several controls mitigate the same ransomware scenario, their individual ALE reductions cannot be interpreted as fully additive enterprise loss avoidance.

---

# Part 1 — The Selection

## Funded Controls

### 1. Network Segmentation

**Cost = $35,000**

Task 7 ALE reduction:

**$2,864,400 − $1,145,760 = $1,718,640**

This control is funded because GAP-003 intersects all five modeled kill chains and prevents a local foothold from automatically becoming enterprise-wide access.

---

### 2. MFA for VPN and Administrative Accounts

**Cost = $10,000**

Task 7 ALE reduction:

**$2,864,400 − $1,432,200 = $1,432,200**

This is funded because existing licensing minimizes incremental cost while directly reducing the credential-abuse paths associated with GAP-007.

---

### 3. Wazuh Enterprise SIEM

**Cost = $21,000**

Task 7 ALE reduction:

**$2,864,400 − $1,861,860 = $1,002,540**

GAP-016 is the highest-ranked threat-informed gap because it intersects:

**5 kill chains + 3 scenarios = 8 modeled correlations.**

The SIEM therefore provides detection coverage across multiple attack paths rather than protecting only one system.

---

### 4. Endpoint Detection and Response Upgrade

**Cost = $26,000**

Task 7 ALE reduction:

**$2,864,400 − $2,005,080 = $859,320**

The EDR upgrade is funded because ransomware execution, credential dumping, malicious processes, and server compromise remain plausible even after segmentation and MFA are introduced.

---

### 5. Dedicated Westside Firewall

**Cost = $20,000**

Task 7 ALE reduction:

**$2,864,400 − $2,721,180 = $143,220**

The established remediation plan independently budgets the Westside enterprise firewall replacement at **$20,000**, because the current consumer-grade router terminates a trusted VPN into Central.

---

### 6. Offsite Immutable Backup Replication

**Cost = $8,000**

Task 7 ALE reduction:

**$135,143 − $60,543 = $74,600**

This is funded because it addresses GAP-004 and KC-4: an attacker who compromises production should not also be able to eliminate every viable recovery copy.

---

## Total Funded Spend

**$35,000 + $10,000 + $21,000 + $26,000 + $20,000 + $8,000**

**= $120,000**

Budget:

**$120,000**

Remaining:

**$120,000 − $120,000 = $0**

Therefore:

**Total Spend = $120,000 of $120,000**

**Budget Remaining = $0**

---

## Selection Risk-Reduction Score

Using the individual Task 7 ALE reductions:

**$1,718,640 + $1,432,200 + $1,002,540 + $859,320 + $143,220 + $74,600**

**= $5,230,520**

This **$5,230,520** value is a **control-selection score**, not MedDefense's literal annual loss reduction, because segmentation, MFA, SIEM, EDR, and the Westside firewall all reduce portions of the same enterprise-ransomware ALE.

The underlying ransomware ALE itself is only:

**$9,548,000 × 0.30 = $2,864,400/year**

so claiming that the portfolio eliminates $5,230,520 of unique annual ransomware loss would double-count the same risk. The Task 5 analysis already established the $2,864,400 baseline.

---

# Deferred Control

## 7. Outsourced 24/7 Security Operations Center

**Cost = $136,960**

The SOC cannot fit within the current annual budget because:

**$136,960 − $120,000 = $16,960**

Therefore, even if MedDefense spent the entire annual security budget on the SOC and funded nothing else, it would still be:

**$16,960 over budget**

Task 7 ALE reduction:

**$1,303,302 − $1,107,807 = $195,495**

**Decision: Defer to the next fiscal year.**

The SOC has positive modeled financial value, but it should follow SIEM and EDR deployment. MedDefense should first generate centralized telemetry and endpoint detections, then determine whether alert volume and after-hours activity justify continuous outsourced monitoring.

---

# Rejected Control

## 8. Full Medical-Device Isolation with Dedicated Monitoring

**Cost = $95,000**

Task 7 ALE reduction:

**$85,000 − $25,500 = $59,500**

Net Value:

**$59,500 − $95,000 = −$35,500**

Because:

**$59,500 < $95,000**

the full architecture costs:

**$95,000 − $59,500 = $35,500**

more annually than its modeled ALE reduction.

**Decision: Reject the $95,000 control package as proposed.**

This does **not** mean MedDefense should accept uncontrolled medical-device risk. The vulnerability plan already contains narrower Alaris and Philips measures costing:

**$12,000 + $15,000 = $27,000**

which is substantially less than the proposed full architecture.

The funded enterprise segmentation program also includes a medical-device zone, so rejecting the $95,000 dedicated architecture does not mean medical devices receive no protection.

---

# Part 2 — Opportunity Cost

The only control formally **deferred** rather than rejected is the outsourced 24/7 SOC.

Task 7 modeled its additional ALE reduction after SIEM and EDR as:

**$1,303,302 − $1,107,807 = $195,495/year**

Therefore:

> **By deferring the outsourced 24/7 SOC, MedDefense accepts an estimated $195,495 in annual risk exposure under the Task 7 SOC model.**

This figure should not be added directly to the remaining ALE from segmentation, MFA, or EDR because all of those controls address overlapping portions of the same ransomware risk.

The full medical-device architecture is not an opportunity-cost deferral because it is rejected on cost-benefit grounds:

**ALE Reduction = $59,500**

**Control Cost = $95,000**

**Net Value = $59,500 − $95,000 = −$35,500**

The rational response is therefore to use a less expensive medical-device control design rather than reserve $95,000 for the same package next year.

---

# Part 3 — Alternative Allocation

A strong alternative is to fund the same portfolio **without the Westside firewall in the current year**.

The alternative would fund:

- Network segmentation: **$35,000**
- MFA: **$10,000**
- Wazuh SIEM: **$21,000**
- EDR: **$26,000**
- Immutable backup: **$8,000**

Alternative total:

**$35,000 + $10,000 + $21,000 + $26,000 + $8,000**

**= $100,000**

Remaining budget:

**$120,000 − $100,000 = $20,000**

## Alternative Task 7 Risk-Reduction Score

**$1,718,640 + $1,432,200 + $1,002,540 + $859,320 + $74,600**

**= $5,087,300**

Primary portfolio score:

**$5,230,520**

Difference:

**$5,230,520 − $5,087,300 = $143,220**

Therefore, the alternative saves:

**$120,000 − $100,000 = $20,000**

while giving up only:

**$143,220**

of the independent Task 7 ALE-reduction score.

As a percentage of the primary score:

**$143,220 ÷ $5,230,520 × 100 ≈ 2.74%**

As a percentage of budget saved:

**$20,000 ÷ $120,000 × 100 ≈ 16.67%**

Thus the alternative spends approximately:

**16.67% less**

for approximately:

**2.74% less**

of the Task 7 control-benefit score.

---

## Overlap-Adjusted Comparison

The alternative becomes even more attractive when overlapping ransomware benefits are treated sequentially.

Starting enterprise ransomware ALE:

**$2,864,400**

After segmentation, the residual is:

**$2,864,400 × 40% = $1,145,760**

After MFA:

**$1,145,760 × 50% = $572,880**

After SIEM:

**$572,880 × 65% = $372,372**

After EDR:

**$372,372 × 70% = $260,660.40**

Therefore, the four main overlapping controls reduce the ransomware ALE by:

**$2,864,400 − $260,660.40**

**= $2,603,739.60**

Adding the Westside firewall's assumed 5% incremental ARO improvement reduces the remaining $260,660.40 by:

**$260,660.40 × 5% = $13,033.02**

Residual with Westside:

**$260,660.40 − $13,033.02 = $247,627.38**

Therefore, once the stronger controls are already funded, the Westside firewall's **marginal modeled ransomware benefit is approximately $13,033.02/year**, not the standalone **$143,220/year** figure.

That means the alternative saves:

**$20,000**

while giving up only approximately:

**$13,033.02**

of incremental modeled ransomware reduction under the overlap-adjusted portfolio.

---

# Budget Recommendation

## Primary Allocation

| Decision | Control | Cost | Task 7 ALE Reduction |
|---|---|---:|---:|
| **Fund** | Network segmentation | **$35,000** | **$2,864,400 − $1,145,760 = $1,718,640** |
| **Fund** | MFA | **$10,000** | **$2,864,400 − $1,432,200 = $1,432,200** |
| **Fund** | Wazuh SIEM | **$21,000** | **$2,864,400 − $1,861,860 = $1,002,540** |
| **Fund** | EDR | **$26,000** | **$2,864,400 − $2,005,080 = $859,320** |
| **Fund** | Westside firewall | **$20,000** | **$2,864,400 − $2,721,180 = $143,220** |
| **Fund** | Immutable backup | **$8,000** | **$135,143 − $60,543 = $74,600** |
| **Defer** | 24/7 SOC | **$136,960** | **$1,303,302 − $1,107,807 = $195,495** |
| **Reject as proposed** | Full medical-device architecture | **$95,000** | **$85,000 − $25,500 = $59,500** |

Primary funded spend:

**$35,000 + $10,000 + $21,000 + $26,000 + $20,000 + $8,000 = $120,000**

Budget remaining:

**$120,000 − $120,000 = $0**

---

# Final Management Decision

Under the original Task 7 scoring model, the recommended six-control package uses:

**$120,000 ÷ $120,000 = 100%**

of the available security budget and provides the highest feasible combined independent ALE-reduction score:

**$5,230,520**

subject to the important warning that this figure contains overlapping benefits.

The principal trade-off is the SOC. By deferring it, MedDefense accepts an estimated:

**$1,303,302 − $1,107,807 = $195,495/year**

of additional modeled exposure, but avoids committing:

**$136,960 − $120,000 = $16,960**

more than the entire annual budget to a single capability.

The most financially efficient alternative is to defer the Westside firewall as well, spending:

**$100,000**

instead of:

**$120,000**

and retaining:

**$120,000 − $100,000 = $20,000**

for contingency or targeted medical-device work.

Because the overlap-adjusted marginal benefit of the Westside firewall after segmentation, MFA, SIEM, and EDR is only:

**$260,660.40 × 5% = $13,033.02/year**

the **$100,000 alternative allocation** offers nearly the same modeled portfolio protection at lower cost.

The Board therefore has two defensible choices:

**Strict maximum under the Task 7 standalone scoring:** spend the full **$120,000**.

**More conservative portfolio allocation after accounting for overlapping controls:** spend **$100,000**, retain **$20,000**, and reconsider the Westside firewall against emerging threat and implementation data.

Both decisions preserve the core investment priority: fund controls that break MedDefense's repeated ransomware, credential, lateral-movement, detection, and recovery attack paths before purchasing higher-cost capabilities with weaker marginal returns.
