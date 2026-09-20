# MedDefense Health Systems  
## Task 5 — The Risk Equation

### Method

The following formulas are used throughout:

**SLE = Asset Value (AV) × Exposure Factor (EF)**

**ALE = Single Loss Expectancy (SLE) × Annualized Rate of Occurrence (ARO)**

Where the source provides a range, the analysis states the assumption used rather than hiding the judgment behind a single number.

---

# Scenario 1 — Ransomware Attack on Billing Server

**Asset:** `billing-srv-01`  
**Threat:** BlackReef-style ransomware group

## 1. Asset Value

The server processes **$4.2 million per year**, but the entire $4.2 million should not be treated as lost in one ransomware incident. The scenario specifically supplies the losses expected from an outage: downtime, recovery, and regulatory consequences.

Downtime loss:

**18 days × $16,000/day = $288,000**

Recovery cost:

**$85,000**

Assumed HIPAA penalty:

**$100,000**

Therefore:

**AV = $288,000 + $85,000 + $100,000 = $473,000**

I use **$473,000** as the risk-specific asset value. This assumes that the 18 days of billing disruption represent actual economic loss rather than merely delayed collections.

## 2. Exposure Factor

A successful ransomware incident of the modeled severity triggers essentially the entire loss bundle: downtime, reconstruction/forensics, and the assumed regulatory cost.

Therefore:

**EF = 100% = 1.00**

## 3. Single Loss Expectancy

**SLE = AV × EF**

**SLE = $473,000 × 1.00 = $473,000**

One successful ransomware incident is therefore modeled to cost approximately **$473,000**.

## 4. Annualized Rate of Occurrence

The source estimates one ransomware event every three to four years.

Three-year rate:

**ARO = 1 ÷ 3 = 0.333**

Four-year rate:

**ARO = 1 ÷ 4 = 0.250**

Using the midpoint recurrence interval:

**(3 years + 4 years) ÷ 2 = 3.5 years**

Therefore:

**ARO = 1 ÷ 3.5 = 0.286**

## 5. Annualized Loss Expectancy

**ALE = SLE × ARO**

**ALE = $473,000 × 0.286 = approximately $135,143 per year**

The plausible range from the supplied three-to-four-year frequency is:

**$473,000 × 0.250 = $118,250/year**

to

**$473,000 × 0.333 = approximately $157,509/year**

## 6. Confidence

**Confidence: Medium**

The incident-cost inputs are relatively concrete, but the ARO is sector-derived rather than measured from MedDefense's own event history.

The assumption with the greatest effect is whether **18 × $16,000 = $288,000** represents permanently lost billing revenue or delayed collections. If much of that revenue can later be recovered, the SLE and ALE would decline significantly.

---

# Scenario 2 — Patient Data Breach via EHR System

**Asset:** `ehr-srv-01` + `ehr-db-01`  
**Threat:** External attacker or malicious insider exfiltrating patient data

## 1. Asset Value

The EHR contains approximately 50,000 patient records.

Record-related breach cost:

**50,000 records × $165/record = $8,250,000**

Breach-notification infrastructure and credit monitoring:

**$25,000**

Estimated litigation:

**$200,000**

Estimated patient attrition:

**$600,000**

Therefore:

**AV = $8,250,000 + $25,000 + $200,000 + $600,000**

**AV = $9,075,000**

This is a much more meaningful EHR value than server replacement cost because the principal economic exposure is the information breach, legal consequences, notification obligations, and loss of patient business.

## 2. Exposure Factor

The scenario represents a breach of the approximately 50,000-record EHR population and assumes the associated response, litigation, and reputational consequences occur.

Therefore:

**EF = 100% = 1.00**

## 3. Single Loss Expectancy

**SLE = $9,075,000 × 1.00**

**SLE = $9,075,000**

## 4. Annualized Rate of Occurrence

The supplied estimate is one breach every three years.

**ARO = 1 ÷ 3 = 0.333**

## 5. Annualized Loss Expectancy

**ALE = $9,075,000 × 0.333**

More exactly:

**ALE = $9,075,000 ÷ 3 = $3,025,000 per year**

## 6. Confidence

**Confidence: Medium**

The arithmetic is strong, but the loss estimate contains substantial modeling uncertainty.

The largest assumption is the breach valuation. The supplied **$165-per-record** value already includes lost-business effects, while the scenario separately provides **$600,000** of MedDefense-specific patient attrition. There is therefore some possibility of overlap.

If the separate $600,000 reputation estimate were excluded to avoid possible double counting:

**Revised AV = $8,250,000 + $25,000 + $200,000 = $8,475,000**

and:

**Revised ALE = $8,475,000 ÷ 3 = $2,825,000/year**

The supplied assumptions therefore support an ALE of **$3,025,000/year**, but the treatment of reputational loss is the most important valuation uncertainty.

---

# Scenario 3 — Negligent Insider Data Theft

**Asset:** Patient data accessible through clinical workstations  
**Threat:** Negligent insider

## 1. Asset Value

The source supplies an average healthcare negligent-insider incident cost of $120,000, composed of:

**$30,000 investigation + $25,000 containment + $40,000 remediation + $25,000 regulatory reporting**

Therefore:

**AV = $30,000 + $25,000 + $40,000 + $25,000**

**AV = $120,000**

Because the source does not provide a total patient-record population for a typical negligent event, the average incident cost is the most defensible risk-specific AV proxy.

## 2. Exposure Factor

The $120,000 represents the full modeled cost of one negligent insider incident.

Therefore:

**EF = 100% = 1.00**

## 3. Single Loss Expectancy

**SLE = $120,000 × 1.00**

**SLE = $120,000**

## 4. Annualized Rate of Occurrence

The supplied estimate is two to three negligent incidents per year.

Using the midpoint:

**ARO = (2 + 3) ÷ 2 = 2.5 incidents/year**

Unlike many cyber risks, this ARO is greater than 1 because multiple separate incidents can occur during one year.

## 5. Annualized Loss Expectancy

**ALE = $120,000 × 2.5**

**ALE = $300,000 per year**

Frequency sensitivity is:

At two incidents annually:

**$120,000 × 2 = $240,000/year**

At three incidents annually:

**$120,000 × 3 = $360,000/year**

## 6. Confidence

**Confidence: Medium**

The loss-per-event figure is relatively clear, but MedDefense's actual incident frequency is estimated from sector experience rather than organization-specific historical measurement.

The assumption that changes the ALE most dramatically is therefore the **ARO**. Moving from two to three events per year changes the annual loss estimate from:

**$240,000 to $360,000**

which is a difference of:

**$360,000 − $240,000 = $120,000/year**

---

# Scenario 4 — Medical Device Compromise

**Asset:** Seven BD Alaris infusion pumps plus the associated clinical service  
**Threat:** Opportunistic attacker exploiting weak credentials and network access

This scenario should be modeled as **two separate loss events** because denial of service and patient injury have radically different impact and frequency.

## Shared Asset Value

Physical replacement value:

**7 pumps × $15,000/pump = $105,000**

Patient-safety liability is provided as $500,000–$5,000,000. Using the midpoint for the base model:

**($500,000 + $5,000,000) ÷ 2 = $2,750,000**

FDA investigation:

**$150,000**

Five days of operational disruption:

**5 days × $20,000/day = $100,000**

Therefore, the complete economic value exposed is:

**AV = $105,000 + $2,750,000 + $150,000 + $100,000**

**AV = $3,105,000**

The exposure factor changes according to the event.

---

## Scenario 4A — Medical Device Denial of Service

A DoS event is assumed to cause quarantine/investigation and operational disruption but not pump destruction or patient injury.

Loss from FDA investigation:

**$150,000**

Operational disruption:

**5 × $20,000 = $100,000**

Total expected DoS loss:

**$150,000 + $100,000 = $250,000**

### Exposure Factor

**EF = $250,000 ÷ $3,105,000**

**EF = 0.0805 = approximately 8.05%**

### Single Loss Expectancy

**SLE = $3,105,000 × 0.0805**

**SLE = approximately $250,000**

### ARO

The supplied probability is once every ten years:

**ARO = 1 ÷ 10 = 0.10**

### ALE

**ALE = $250,000 × 0.10**

**ALE = $25,000 per year**

### Confidence

**Confidence: Medium**

The supplied frequency is explicit, and the disruption cost is straightforward.

The most important assumption is whether a DoS incident actually triggers the full **$150,000 FDA investigation cost**. If it did not, the loss would instead be:

**SLE = 5 × $20,000 = $100,000**

and:

**ALE = $100,000 × 0.10 = $10,000/year**

---

## Scenario 4B — Patient-Safety Incident

Using the midpoint liability assumption:

**Liability = ($500,000 + $5,000,000) ÷ 2 = $2,750,000**

Add investigation:

**$2,750,000 + $150,000 = $2,900,000**

Add operational disruption:

**$2,900,000 + (5 × $20,000) = $3,000,000**

The pumps are not assumed to be physically destroyed, so the $105,000 replacement value remains outside the modeled SLE.

### Exposure Factor

**EF = $3,000,000 ÷ $3,105,000**

**EF = 0.9662 = approximately 96.62%**

### Single Loss Expectancy

**SLE = $3,105,000 × 0.9662**

**SLE = approximately $3,000,000**

### ARO

The supplied probability is once every fifty years:

**ARO = 1 ÷ 50 = 0.02**

### ALE

**ALE = $3,000,000 × 0.02**

**ALE = $60,000 per year**

### Confidence

**Confidence: Low**

The liability range is extremely broad, making this ALE highly sensitive to severity.

At the low liability estimate:

**SLE = $500,000 + $150,000 + $100,000 = $750,000**

**ALE = $750,000 × 0.02 = $15,000/year**

At the high liability estimate:

**SLE = $5,000,000 + $150,000 + $100,000 = $5,250,000**

**ALE = $5,250,000 × 0.02 = $105,000/year**

Therefore the patient-safety ALE could reasonably range from:

**$15,000/year to $105,000/year**

under the supplied liability assumptions.

### Combined Medical-Device ALE

Using the midpoint patient-safety model:

**DoS ALE + Patient-Safety ALE**

**$25,000 + $60,000 = $85,000/year**

This figure should be treated as a planning estimate rather than a precise forecast because the patient-safety component has low confidence.

---

# Scenario 5 — VPN Compromise Leading to Full Network Access

**Asset:** Entire MedDefense internal environment reachable through the FortiGate VPN  
**Threat:** External VPN exploitation or credential compromise

The scenario explicitly instructs that the maximum impact should aggregate Scenarios 1 and 2 because a full campaign can combine ransomware disruption with EHR data theft.

## 1. Asset Value

Scenario 1 economic exposure:

**$288,000 downtime + $85,000 recovery + $100,000 penalty = $473,000**

Scenario 2 economic exposure:

**(50,000 × $165) + $25,000 + $200,000 + $600,000 = $9,075,000**

Therefore:

**AV = $473,000 + $9,075,000**

**AV = $9,548,000**

This reflects the FortiGate's role as a gateway rather than treating the firewall appliance itself as the asset of interest.

## 2. Exposure Factor

The modeled scenario is specifically a **full ransomware plus data-exfiltration campaign**, so the base case assumes the complete aggregate loss is realized.

**EF = 100% = 1.00**

## 3. Single Loss Expectancy

**SLE = $9,548,000 × 1.00**

**SLE = $9,548,000**

## 4. Annualized Rate of Occurrence

The source provides:

**ARO = 0.30**

This corresponds approximately to one event every:

**1 ÷ 0.30 = 3.33 years**

## 5. Annualized Loss Expectancy

**ALE = $9,548,000 × 0.30**

**ALE = $2,864,400 per year**

## 6. Confidence

**Confidence: Low to Medium**

The ARO is supplied directly, but the modeled EF assumes a VPN compromise develops into the complete ransomware-plus-EHR-breach outcome.

That scope assumption creates the greatest uncertainty.

For example, if a VPN compromise produced only 50% of the modeled aggregate impact:

**EF = 50% = 0.50**

then:

**SLE = $9,548,000 × 0.50 = $4,774,000**

and:

**ALE = $4,774,000 × 0.30 = $1,432,200/year**

The difference between the full-impact and half-impact assumptions is:

**$2,864,400 − $1,432,200 = $1,432,200/year**

Therefore, the percentage of successful VPN compromises that progress to full enterprise impact is the most important assumption in this scenario.

---

# Quantitative Risk Summary

| Scenario | AV | EF | SLE | ARO | ALE | Confidence |
|---|---:|---:|---:|---:|---:|---|
| **1. Billing ransomware** | **$288,000 + $85,000 + $100,000 = $473,000** | **100%** | **$473,000 × 1.00 = $473,000** | **1 ÷ 3.5 = 0.286** | **$473,000 × 0.286 ≈ $135,143/year** | Medium |
| **2. EHR breach** | **(50,000 × $165) + $25,000 + $200,000 + $600,000 = $9,075,000** | **100%** | **$9,075,000 × 1.00 = $9,075,000** | **1 ÷ 3 = 0.333** | **$9,075,000 ÷ 3 = $3,025,000/year** | Medium |
| **3. Negligent insider** | **$30,000 + $25,000 + $40,000 + $25,000 = $120,000** | **100%** | **$120,000 × 1.00 = $120,000** | **(2 + 3) ÷ 2 = 2.5** | **$120,000 × 2.5 = $300,000/year** | Medium |
| **4A. Medical-device DoS** | **$105,000 + $2,750,000 + $150,000 + $100,000 = $3,105,000** | **$250,000 ÷ $3,105,000 = 8.05%** | **$3,105,000 × 8.05% ≈ $250,000** | **1 ÷ 10 = 0.10** | **$250,000 × 0.10 = $25,000/year** | Medium |
| **4B. Patient-safety event** | **$3,105,000** | **$3,000,000 ÷ $3,105,000 = 96.62%** | **$3,105,000 × 96.62% ≈ $3,000,000** | **1 ÷ 50 = 0.02** | **$3,000,000 × 0.02 = $60,000/year** | Low |
| **4. Combined medical-device risk** | Two event modes | — | — | — | **$25,000 + $60,000 = $85,000/year** | Low |
| **5. VPN-to-enterprise compromise** | **$473,000 + $9,075,000 = $9,548,000** | **100%** | **$9,548,000 × 1.00 = $9,548,000** | **0.30** | **$9,548,000 × 0.30 = $2,864,400/year** | Low–Medium |

# Management Interpretation

The calculations demonstrate why qualitative severity alone is insufficient for budgeting. The highest annualized exposures are driven not necessarily by the most expensive individual incident but by the combination of **impact and frequency**.

The EHR breach model produces:

**$9,075,000 × 0.333 = $3,025,000/year**

while the VPN compromise model produces:

**$9,548,000 × 0.30 = $2,864,400/year**

The negligent-insider model produces:

**$120,000 × 2.5 = $300,000/year**

because relatively modest incidents can create significant annual loss when they occur repeatedly.

One important caution is that Scenario 5 overlaps Scenarios 1 and 2. Its **$9,548,000 = $473,000 + $9,075,000** SLE deliberately aggregates those consequences because the VPN is the pathway into them. Therefore, the three ALEs should **not simply be added together** when calculating an enterprise-wide total; doing so would count some of the same ransomware and EHR losses more than once.

The practical value of these ALEs is in the next decision step: comparing the **current ALE** with the **residual ALE after a proposed control**, then comparing the annual risk reduction with the control's annualized cost. That converts MedDefense's security roadmap from “Critical/High” findings into defensible investment decisions.
