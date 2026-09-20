# MedDefense Health Systems  
## Task 6 — The ALE Workshop

### Quantitative Method

The analysis uses:

**SLE = Asset Value (AV) × Exposure Factor (EF)**

**ALE = Single Loss Expectancy (SLE) × Annualized Rate of Occurrence (ARO)**

**Net Benefit = ALE Before Control − ALE After Control − Annual Control Cost**

The underlying asset-loss values and baseline frequencies were established in Task 5.

The remediation files provide **implementation planning costs**, not recurring annual total-cost-of-ownership figures. Therefore, this workshop treats the documented implementation cost as the **Year-1 annual control cost**. No unsupported recurring license or staffing cost is invented.

Residual-risk percentages are analyst estimates. They are explicitly stated so that management can replace them later with observed MedDefense data.

---

# Risk 1 — EHR PHI Breach Through Excessive Database Reachability

**Risk:** External attacker or ransomware operator obtains internal access and exfiltrates the EHR patient database.

**Source:** **GAP-006 — Excessive EHR database reachability + Finding 003 — PostgreSQL unrestricted network access + TA-1 Ransomware / TA-2 Nation-State APT + KC-1 FortiGate VPN → EHR Database Compromise.**

T15 upgraded GAP-006 from High to Critical because `ehr-db-01:5432` is directly used in both the ransomware and sophisticated third-party/APT scenarios.

## Asset

**Asset:** AST-001 `ehr-srv-01`, AST-002 `ehr-db-01`, and the associated EHR patient-record environment.

### Asset Value

Patient-record breach cost:

**50,000 records × $165/record = $8,250,000**

Breach notification and credit-monitoring infrastructure:

**$25,000**

Litigation exposure:

**$200,000**

Patient trust/reputational loss:

**$600,000**

Therefore:

**AV = $8,250,000 + $25,000 + $200,000 + $600,000**

**AV = $9,075,000**

The AV represents the economic exposure associated with the EHR information, not the physical replacement cost of two servers.

## Exposure Factor

A modeled breach of the full EHR population triggers essentially the entire loss bundle.

**EF = 100% = 1.00**

## Single Loss Expectancy

**SLE = AV × EF**

**SLE = $9,075,000 × 1.00**

**SLE = $9,075,000**

## Annualized Rate of Occurrence

The Task 5 baseline was approximately one material breach every three years.

**ARO = 1 ÷ 3**

**ARO = 0.333**

## Annualized Loss Expectancy

**ALE = SLE × ARO**

**ALE = $9,075,000 × 0.333**

Using the exact one-in-three-year rate:

**ALE = $9,075,000 ÷ 3**

**ALE = $3,025,000 per year**

## Proposed Control

Restrict PostgreSQL so that TCP/5432 is accessible only from explicitly authorized EHR application and administrative systems. Replace the current `/16` access rule and enforce host/network firewall restrictions.

The documented Year-1 implementation cost is:

**Control Annual Cost = $4,000**

## Estimated ALE After Control

The control directly removes the unnecessary lateral-movement path used by KC-1, but it does not eliminate application compromise, valid credential abuse, malicious insiders, or vendor-originated access.

I therefore assume a **60% reduction in occurrence probability**, leaving 40% of the baseline ARO.

Residual ARO:

**0.333 × (1 − 0.60) = 0.333 × 0.40**

Using the exact one-in-three rate:

**Residual ARO = (1 ÷ 3) × 0.40 = 0.1333**

Residual ALE:

**$9,075,000 × 0.1333 ≈ $1,210,000 per year**

## Net Benefit

**Net Benefit = ALE Before − ALE After − Control Cost**

**Net Benefit = $3,025,000 − $1,210,000 − $4,000**

**Net Benefit = $1,811,000 in Year 1**

### Decision Interpretation

A **$4,000** database-access restriction is modeled to reduce annualized risk by:

**$3,025,000 − $1,210,000 = $1,815,000**

After control cost:

**$1,815,000 − $4,000 = $1,811,000 net benefit**

This is one of the strongest risk-reduction investments in the current plan.

---

# Risk 2 — Enterprise Ransomware Following VPN or Internal Foothold

**Risk:** A BlackReef-style ransomware operator gains an internal foothold, moves across the flat network, compromises identity and recovery infrastructure, steals EHR information, and encrypts enterprise systems.

**Source:** **GAP-003 + GAP-007 + GAP-004 + GAP-016; Findings 003, 007 and 015; TA-1 Ransomware; KC-1 FortiGate → EHR and KC-4 Administrator → Backup Destruction.**

T15 ranks network isolation second overall because GAP-003 intersects:

**5 of 5 kill chains + 2 of 3 scenarios = 7 modeled correlations.**

## Asset

**Asset:** The MedDefense internal environment reachable through the FortiGate and flat `10.10.0.0/16` architecture.

### Asset Value

Billing ransomware exposure from Task 5:

**$288,000 downtime + $85,000 recovery + $100,000 regulatory penalty = $473,000**

EHR breach exposure:

**$8,250,000 record cost + $25,000 notification + $200,000 litigation + $600,000 reputation**

**= $9,075,000**

Aggregate full-campaign exposure:

**AV = $473,000 + $9,075,000**

**AV = $9,548,000**

## Exposure Factor

The modeled event is a successful full ransomware-plus-exfiltration campaign.

**EF = 100% = 1.00**

## Single Loss Expectancy

**SLE = $9,548,000 × 1.00**

**SLE = $9,548,000**

## Annualized Rate of Occurrence

The established VPN/full-network baseline is:

**ARO = 0.30**

Equivalent recurrence interval:

**1 ÷ 0.30 = 3.33 years per event**

## Annualized Loss Expectancy

**ALE = $9,548,000 × 0.30**

**ALE = $2,864,400 per year**

## Proposed Control

Implement the first-year **critical-zone segmentation and containment package** already represented in the remediation plan:

- MRI isolation: **$25,000**
- EHR PostgreSQL restriction: **$4,000**
- Philips medical-device segmentation: **$15,000**
- NAS management isolation: **$4,000**
- Westside enterprise perimeter replacement: **$20,000**

Year-1 control cost:

**$25,000 + $4,000 + $15,000 + $4,000 + $20,000**

**Control Annual Cost = $68,000**

## Estimated ALE After Control

Segmentation does not necessarily stop the attacker from initially compromising VPN infrastructure. Its primary effect is reducing the percentage of the enterprise loss realized after that compromise.

I therefore leave ARO unchanged:

**Residual ARO = 0.30**

and assume the blast radius falls by 60%, changing EF from 100% to 40%.

**Residual EF = 100% × (1 − 0.60)**

**Residual EF = 40%**

Residual SLE:

**$9,548,000 × 0.40 = $3,819,200**

Residual ALE:

**$3,819,200 × 0.30 = $1,145,760 per year**

## Net Benefit

**Net Benefit = $2,864,400 − $1,145,760 − $68,000**

**Net Benefit = $1,650,640 in Year 1**

### Decision Interpretation

The modeled annual risk reduction before control cost is:

**$2,864,400 − $1,145,760 = $1,718,640**

After the first-year segmentation investment:

**$1,718,640 − $68,000 = $1,650,640 net benefit**

The financial result supports T15's qualitative conclusion that segmentation is MedDefense's highest-leverage preventive control.

---

# Risk 3 — Insider PHI Exfiltration Through Uncontrolled Removable Media

**Risk:** A negligent or malicious insider removes Restricted patient information from a clinical workstation without DLP or effective removable-media control.

**Source:** **GAP-014 — No DLP for bulk Restricted-data extraction + Finding 023 — unrestricted USB mass storage + TA-4 Negligent Insider / TA-3 Malicious Insider.**

T15 upgraded GAP-014 from High to Critical because data exfiltration appears across all three major threat scenarios:

**S-1 + S-2 + S-3 = 3 of 3 scenarios.**

## Asset

**Asset:** Patient information accessible through approximately 280 clinical workstations.

### Asset Value

Task 5 established average negligent-insider incident cost as:

Investigation:

**$30,000**

Containment:

**$25,000**

Remediation:

**$40,000**

Regulatory reporting:

**$25,000**

Therefore:

**AV = $30,000 + $25,000 + $40,000 + $25,000**

**AV = $120,000 per incident**

## Exposure Factor

The $120,000 value already represents the modeled full cost of one event.

**EF = 100% = 1.00**

## Single Loss Expectancy

**SLE = $120,000 × 1.00**

**SLE = $120,000**

## Annualized Rate of Occurrence

The established baseline is two to three negligent events per year.

Midpoint:

**ARO = (2 + 3) ÷ 2**

**ARO = 2.5 incidents/year**

## Annualized Loss Expectancy

**ALE = $120,000 × 2.5**

**ALE = $300,000 per year**

## Proposed Control

Deploy centrally managed removable-media control with role-based clinical exceptions and audit logging.

The documented first-year cost is:

**Control Annual Cost = $12,000**

## Estimated ALE After Control

USB control eliminates an important physical exfiltration route but does not prevent all negligent disclosures. Users may still make mistakes through application exports, email, cloud services, or other authorized channels.

I therefore assume a conservative **40% reduction in ARO**, leaving 60% of current event frequency.

Residual ARO:

**2.5 × (1 − 0.40)**

**2.5 × 0.60 = 1.5 incidents/year**

Residual ALE:

**$120,000 × 1.5**

**Residual ALE = $180,000 per year**

## Net Benefit

**Net Benefit = $300,000 − $180,000 − $12,000**

**Net Benefit = $108,000 in Year 1**

### Decision Interpretation

Annualized risk reduction:

**$300,000 − $180,000 = $120,000**

After control cost:

**$120,000 − $12,000 = $108,000 net benefit**

The control is financially favorable even though it addresses only one exfiltration channel.

---

# Risk 4 — Billing Server Ransomware Through the Apache Exploit Chain

**Risk:** An external or opportunistic attacker exploits Apache on `billing-srv-01`, gains execution as `www-data`, escalates to root, and uses the compromised server for ransomware or lateral movement.

**Source:** **GAP-011 — Vulnerability/Patch Management + GAP-008 — Billing Server Detection/Egress Weakness + Findings 001 and 002 + TA-1 Ransomware / TA-6 Opportunistic Attacker.**

Findings 001 and 002 form a documented chain:

**Finding 001 RCE → execution as `www-data` → Finding 002 privilege escalation → root**

and were deliberately scheduled for the same maintenance window.

## Asset

**Asset:** AST-004 `billing-srv-01`.

### Asset Value

Billing downtime:

**18 days × $16,000/day = $288,000**

Recovery and forensic cost:

**$85,000**

Assumed regulatory penalty:

**$100,000**

Therefore:

**AV = $288,000 + $85,000 + $100,000**

**AV = $473,000**

## Exposure Factor

The modeled ransomware incident is assumed to incur the full loss bundle.

**EF = 100% = 1.00**

## Single Loss Expectancy

**SLE = $473,000 × 1.00**

**SLE = $473,000**

## Annualized Rate of Occurrence

Sector frequency was one event every three to four years.

Midpoint recurrence:

**(3 + 4) ÷ 2 = 3.5 years**

ARO:

**1 ÷ 3.5 = 0.286**

## Annualized Loss Expectancy

**ALE = $473,000 × 0.286**

Using the exact fraction:

**$473,000 ÷ 3.5 = $135,142.86**

**ALE ≈ $135,143 per year**

## Proposed Control

Patch both Apache vulnerabilities in the same maintenance window.

Finding 001 cost:

**$4,000**

Finding 002 incremental cost:

**$1,000**

Therefore:

**Control Annual Cost = $4,000 + $1,000**

**Control Annual Cost = $5,000**

## Estimated ALE After Control

Because the proposed change removes the exact documented RCE-to-root chain but cannot eliminate phishing, stolen credentials, new vulnerabilities, or other attack paths, I assume a **70% reduction in ARO**.

Residual ARO:

**0.286 × (1 − 0.70)**

**0.286 × 0.30 ≈ 0.0857**

Using the exact original rate:

**(1 ÷ 3.5) × 0.30 = 0.0857**

Residual ALE:

**$473,000 × 0.0857 ≈ $40,543 per year**

## Net Benefit

**Net Benefit = $135,143 − $40,543 − $5,000**

**Net Benefit = $89,600 in Year 1**

### Decision Interpretation

Risk reduction before cost:

**$135,143 − $40,543 = $94,600**

After spending $5,000:

**$94,600 − $5,000 = $89,600 net benefit**

The economic case supports immediate remediation of the chained findings rather than treating them as two unrelated technical tickets.

---

# Risk 5 — Alaris Medical-Device Compromise

**Risk:** An opportunistic or ransomware attacker reaches the infusion-pump environment, abuses default credentials or network trust, and causes device disruption or a patient-safety incident.

**Source:** **GAP-002 — Medical IoT segmentation/monitoring/recovery + GAP-015 — Medical-device credential governance + Finding 010 — Alaris default credentials and inadequate isolation + TA-6 Opportunistic Attacker / TA-1 Ransomware.**

The vulnerability assessment confirmed that tested Alaris pumps used default credentials and remained insufficiently isolated. The medical-IoT gap remains Critical because the assets directly support patient treatment.

## Asset

**Asset:** Seven assessed BD Alaris infusion pumps and the clinical service they support.

The risk has two event modes, so the ALE must be calculated separately and then combined.

### Shared Asset Value

Physical device value:

**7 pumps × $15,000/pump = $105,000**

Midpoint patient-safety liability:

**($500,000 + $5,000,000) ÷ 2 = $2,750,000**

Investigation exposure:

**$150,000**

Operational disruption:

**5 days × $20,000/day = $100,000**

Economic value exposed:

**AV = $105,000 + $2,750,000 + $150,000 + $100,000**

**AV = $3,105,000**

---

## Event Mode A — Device Denial of Service

DoS loss:

**$150,000 investigation + $100,000 disruption = $250,000**

Exposure Factor:

**EF = $250,000 ÷ $3,105,000**

**EF = 8.05%**

SLE:

**$3,105,000 × 8.05% ≈ $250,000**

ARO:

**1 ÷ 10 years = 0.10**

ALE:

**$250,000 × 0.10 = $25,000/year**

---

## Event Mode B — Patient-Safety Incident

Patient-safety loss:

**$2,750,000 liability + $150,000 investigation + $100,000 disruption**

**= $3,000,000**

Exposure Factor:

**$3,000,000 ÷ $3,105,000 = 96.62%**

SLE:

**$3,105,000 × 96.62% ≈ $3,000,000**

ARO:

**1 ÷ 50 years = 0.02**

ALE:

**$3,000,000 × 0.02 = $60,000/year**

### Current Combined Medical-Device ALE

**$25,000 + $60,000**

**ALE = $85,000 per year**

## Proposed Control

Remove default credentials using vendor-supported procedures and place the pumps in a dedicated VLAN with explicit clinical communication rules.

The documented first-year cost is:

**Control Annual Cost = $12,000**

## Estimated ALE After Control

Because credential replacement plus segmentation directly removes two primary enabling conditions—default administrative access and broad internal reachability—I assume a **70% reduction in occurrence frequency** for both modeled attack modes.

### Residual DoS Risk

Residual ARO:

**0.10 × (1 − 0.70)**

**0.10 × 0.30 = 0.03**

Residual ALE:

**$250,000 × 0.03 = $7,500/year**

### Residual Patient-Safety Risk

Residual ARO:

**0.02 × (1 − 0.70)**

**0.02 × 0.30 = 0.006**

Residual ALE:

**$3,000,000 × 0.006 = $18,000/year**

Combined residual ALE:

**$7,500 + $18,000**

**Estimated ALE After Control = $25,500/year**

## Net Benefit

**Net Benefit = $85,000 − $25,500 − $12,000**

**Net Benefit = $47,500 in Year 1**

### Decision Interpretation

Annualized risk reduction:

**$85,000 − $25,500 = $59,500**

After control cost:

**$59,500 − $12,000 = $47,500 net benefit**

The financial benefit is lower than the EHR or ransomware controls, but the calculation does not fully capture the non-financial significance of potential patient harm.

---

# Risk Prioritization by ALE

| Rank | Risk | Current ALE Calculation | Current ALE | Year-1 Control Cost | Residual ALE | Net Benefit |
|---:|---|---:|---:|---:|---:|---:|
| **1** | **EHR PHI breach** | **$9,075,000 × (1 ÷ 3)** | **$3,025,000** | **$4,000** | **$1,210,000** | **$3,025,000 − $1,210,000 − $4,000 = $1,811,000** |
| **2** | **Enterprise ransomware / VPN-to-network compromise** | **$9,548,000 × 0.30** | **$2,864,400** | **$25K + $4K + $15K + $4K + $20K = $68,000** | **$1,145,760** | **$2,864,400 − $1,145,760 − $68,000 = $1,650,640** |
| **3** | **Insider PHI exfiltration** | **$120,000 × 2.5** | **$300,000** | **$12,000** | **$180,000** | **$300,000 − $180,000 − $12,000 = $108,000** |
| **4** | **Billing-server ransomware** | **$473,000 × (1 ÷ 3.5)** | **≈ $135,143** | **$4,000 + $1,000 = $5,000** | **≈ $40,543** | **$135,143 − $40,543 − $5,000 = $89,600** |
| **5** | **Medical-device compromise** | **($250,000 × 0.10) + ($3,000,000 × 0.02)** | **$85,000** | **$12,000** | **$25,500** | **$85,000 − $25,500 − $12,000 = $47,500** |

# Portfolio Interpretation

The quantitative ranking reinforces, rather than replaces, the threat-informed prioritization from T15. EHR exposure and enterprise ransomware dominate because their single-event consequences are measured in millions of dollars and their estimated recurrence intervals are short enough to create very large annualized losses.

The strongest individual Year-1 economic case is the EHR database restriction:

**Current ALE $3,025,000 − residual ALE $1,210,000 − $4,000 cost = $1,811,000 net benefit.**

The segmentation program follows:

**$2,864,400 − $1,145,760 − $68,000 = $1,650,640 net benefit.**

Those results support funding controls that interrupt the exact attack paths identified in KC-1 rather than selecting controls solely by scanner severity.

The five ALEs should **not be summed into one enterprise total**. Risk 2 deliberately contains some of the EHR and billing consequences modeled separately in Risks 1 and 4. Adding:

**$3,025,000 + $2,864,400 + $300,000 + $135,143 + $85,000**

would produce:

**$6,409,543**

but that figure would double-count overlapping ransomware and EHR consequences and should therefore **not** be presented as MedDefense's total annual cyber risk.

The correct management use is to compare each risk's **before-control ALE**, **after-control ALE**, and **control cost**, while recognizing shared controls. For example, segmentation used in Risk 2 also contributes to reducing Risks 1 and 5, so its benefit cannot be counted independently three times when building the final budget portfolio.

## Final Decision Principle

The quantitative analysis converts the security strategy into an investment question:

**Fund controls where the reduction in expected annual loss materially exceeds the first-year control cost, while also accounting for patient safety and regulatory consequences that cannot be completely represented by dollars.**

For all five modeled risks:

- EHR control net benefit = **$1,811,000**
- Segmentation control net benefit = **$1,650,640**
- Insider control net benefit = **$108,000**
- Billing patching net benefit = **$89,600**
- Medical-device control net benefit = **$47,500**

Each result is positive because, under the stated assumptions:

**ALE Before > ALE After + Control Cost**

That provides the financial bridge from MedDefense's gap and threat analysis to control investment.
