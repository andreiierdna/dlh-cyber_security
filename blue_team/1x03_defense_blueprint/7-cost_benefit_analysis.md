# MedDefense Health Systems  
## Task 7 — The Cost-Benefit Analysis

### Method

A control is financially justified when:

**ALE Reduction = ALE Before − ALE After**

and:

**Net Value = ALE Reduction − Annual Control Cost**

The principal ALE baselines established in Task 6 are:

- Enterprise ransomware / VPN-to-network compromise: **$9,548,000 × 0.30 = $2,864,400/year**
- EHR PHI breach: **$9,075,000 × 0.333 ≈ $3,025,000/year**
- Insider PHI exfiltration: **$120,000 × 2.5 = $300,000/year**
- Billing ransomware: **$473,000 × (1 ÷ 3.5) ≈ $135,143/year**
- Medical-device compromise: **$25,000 DoS ALE + $60,000 patient-safety ALE = $85,000/year**

Because several controls mitigate the same ransomware loss scenario, their individual Net Values must **not** be added together and presented as one portfolio risk reduction. Doing so would double-count overlapping benefits.

---

# Control 1 — Network Segmentation

**Control:** VLAN implementation for server, workstation, medical-device, and guest zones

**CIS Control Reference:** **CIS Control 12 — Network Infrastructure Management**

**Risk(s) Addressed:** Enterprise ransomware/lateral movement; EHR exposure; medical-device exposure; MRI/PACS lateral movement.

MedDefense currently operates an effectively flat internal architecture in which compromise of one system can create proximity to EHR, Active Directory, backups, PACS, and medical devices. T15 ranks internal isolation as the second-highest threat-informed gap because GAP-003 intersects all five kill chains.

## Annual Cost

Planning assumption:

- Network/VLAN/firewall licensing and infrastructure: **$10,000**
- Engineering and implementation: **200 hours × $100/hour = $20,000**
- Annual ACL review, testing, and maintenance: **100 hours × $50/hour = $5,000**

Therefore:

**Annual Cost = $10,000 + $20,000 + $5,000 = $35,000**

This is consistent with the project remediation estimates, which place individual MRI and medical-device segmentation work in the $10,000–$50,000 ranges.

## ALE Impact

Task 6 modeled segmentation as reducing the enterprise ransomware **Exposure Factor from 100% to 40%**, because initial compromise may still occur but the attacker loses broad lateral access.

ALE before:

**$9,548,000 × 100% × 0.30 = $2,864,400**

ALE after:

**$9,548,000 × 40% × 0.30 = $1,145,760**

ALE Reduction:

**$2,864,400 − $1,145,760 = $1,718,640**

## Net Value

**$1,718,640 − $35,000 = $1,683,640**

**Verdict: Justified**

**Recommendation: Implement.** Segmentation produces the highest modeled preventive return because it limits the blast radius of both known and future attack paths rather than addressing one CVE.

---

# Control 2 — MFA on VPN and Administrative Accounts

**CIS Control Reference:** **CIS Control 6 — Access Control Management**

**Risk(s) Addressed:** Enterprise ransomware, Active Directory compromise, credential theft, privileged-account misuse.

Microsoft 365 E3 includes Microsoft Entra ID P1, which supports Conditional Access-based MFA, so MedDefense can use its existing licensing rather than purchase a separate MFA license.

## Annual Cost

Incremental license:

**$0**

Implementation labor:

**80 hours × $75/hour = $6,000**

Training/testing/change support:

**20 hours × $100/hour = $2,000**

Ongoing administration:

**40 hours × $50/hour = $2,000**

Therefore:

**Annual Cost = $0 + $6,000 + $2,000 + $2,000 = $10,000**

## ALE Impact

MFA does not prevent FortiGate exploitation or every endpoint exploit. I therefore assume it reduces the enterprise ransomware ARO by **50%**, principally by breaking stolen-password and privileged-credential attack paths.

Current ARO:

**0.30**

Residual ARO:

**0.30 × (1 − 0.50) = 0.15**

ALE before:

**$9,548,000 × 0.30 = $2,864,400**

ALE after:

**$9,548,000 × 0.15 = $1,432,200**

ALE Reduction:

**$2,864,400 − $1,432,200 = $1,432,200**

## Net Value

**$1,432,200 − $10,000 = $1,422,200**

**Verdict: Justified**

**Recommendation: Implement.** Existing O365 E3 licensing removes the largest normal cost barrier, while MFA directly attacks GAP-007 and the credential-conversion stages of KC-1, KC-2, and KC-4.

---

# Control 3 — Enterprise SIEM Using Wazuh

**CIS Control Reference:** **CIS Control 8 — Audit Log Management**

**Risk(s) Addressed:** Enterprise ransomware, EHR compromise, privileged-account misuse, backup destruction, insider activity.

GAP-016 is MedDefense's highest-ranked threat-informed gap because it intersects:

**5 kill chains + 3 scenarios = 8 modeled correlations.**

Wazuh provides SIEM/XDR capabilities and is free and open source, so this model assigns no software license charge.

## Annual Cost

License:

**$0**

Initial deployment, log onboarding, and detection engineering:

**160 hours × $75/hour = $12,000**

Annual tuning, rule maintenance, and administration:

**120 hours × $75/hour = $9,000**

Therefore:

**Annual Cost = $0 + $12,000 + $9,000 = $21,000**

## ALE Impact

A SIEM does not prevent initial access. Its value is earlier discovery and containment.

I assume effective centralized monitoring reduces the average enterprise incident **Exposure Factor by 35%**, from 100% to 65%.

ALE before:

**$9,548,000 × 100% × 0.30 = $2,864,400**

ALE after:

**$9,548,000 × 65% × 0.30 = $1,861,860**

ALE Reduction:

**$2,864,400 − $1,861,860 = $1,002,540**

## Net Value

**$1,002,540 − $21,000 = $981,540**

**Verdict: Justified**

**Recommendation: Implement.** MedDefense already demonstrated the financial relevance of this control when cryptomining operated for at least two weeks before being discovered through performance degradation rather than a security alert.

---

# Control 4 — Offsite Immutable Backup Replication

**CIS Control Reference:** **CIS Control 11 — Data Recovery**

**Risk(s) Addressed:** Ransomware recovery failure, backup destruction, extended billing/clinical outage.

NAS-01 provides 24 TB of RAID5 storage and shares the Central production network and physical failure domain.

AWS currently lists S3 Glacier Deep Archive storage starting at approximately **$0.00099 per GB-month**, while noting separate request and retrieval charges.

## Annual Cost

Maximum repository capacity used for conservative storage planning:

**24 TB × 1,024 GB/TB = 24,576 GB**

Base storage:

**24,576 GB × $0.00099/GB-month × 12 months = $291.96/year**

Rounded planning components:

- Base storage: **≈ $292**
- Request, retrieval-test, and transfer reserve: **$1,208**
- Backup/cloud configuration and integration: **$3,000**
- Restore testing and annual administration: **$3,500**

Therefore:

**Annual Cost = $292 + $1,208 + $3,000 + $3,500 = $8,000**

The actual bill would depend on stored data volume, change rate, retrievals, object-lock design, and Veeam integration; the project does not provide those quantities.

## ALE Impact

Backups reduce outage and recovery loss, but they do **not** reverse a PHI disclosure or regulatory penalty.

Billing ransomware SLE before:

**$288,000 downtime + $85,000 recovery + $100,000 penalty = $473,000**

Assume immutable recovery reduces downtime and recovery losses by **70%**, leaving 30%, while the $100,000 regulatory component remains.

Residual SLE:

**(($288,000 + $85,000) × 30%) + $100,000**

**= $373,000 × 0.30 + $100,000**

**= $111,900 + $100,000**

**= $211,900**

ARO remains:

**1 ÷ 3.5 = 0.286**

ALE before:

**$473,000 ÷ 3.5 ≈ $135,143**

ALE after:

**$211,900 ÷ 3.5 ≈ $60,543**

ALE Reduction:

**$135,143 − $60,543 = $74,600**

## Net Value

**$74,600 − $8,000 = $66,600**

**Verdict: Justified**

**Recommendation: Implement.** The monetary return is smaller than segmentation or MFA, but this control protects the recovery path after preventive controls have already failed.

---

# Control 5 — Sophos Intercept X / EDR Upgrade

**CIS Control Reference:** **CIS Control 10 — Malware Defenses**

**Risk(s) Addressed:** Ransomware execution, credential dumping, malicious PowerShell/process activity, server compromise.

MedDefense already deploys Sophos on managed Windows workstations, although 15 agents were inactive or not reporting; server-class protection is a documented gap.

For sizing, the documented conventional endpoint population is:

**320 Central workstations + 45 Westside workstations + 120 HQ workstations + 30 HQ laptops = 515 endpoints**

The posture assessment identifies **14 server records**, giving a modeled EDR scope of:

**515 + 14 = 529 conventional endpoints/servers**

excluding thin clients, medical devices, and iPads. 

Public 2026 reseller pricing shows full Sophos Intercept X subscriptions around €61.88 per endpoint/year and roughly €170 per server/year in some channels. Since MedDefense already owns basic Sophos endpoint protection, the calculation below assumes only an incremental upgrade cost rather than repurchasing the full subscription.

## Annual Cost

Incremental endpoint upgrade:

**515 × $30 = $15,450**

Incremental server upgrade:

**14 × $100 = $1,400**

Deployment/tuning labor:

**82 hours × $75/hour = $6,150**

Annual administration:

**$3,000**

Therefore:

**Annual Cost = $15,450 + $1,400 + $6,150 + $3,000**

**Annual Cost = $26,000**

Actual Sophos pricing requires a vendor quote; the $30/$100 figures are planning assumptions for the incremental upgrade.

## ALE Impact

EDR will not prevent all VPN exploitation or identity attacks, so I assume a conservative **30% reduction in enterprise ransomware ARO**.

Current ARO:

**0.30**

Residual ARO:

**0.30 × (1 − 0.30) = 0.21**

ALE before:

**$9,548,000 × 0.30 = $2,864,400**

ALE after:

**$9,548,000 × 0.21 = $2,005,080**

ALE Reduction:

**$2,864,400 − $2,005,080 = $859,320**

## Net Value

**$859,320 − $26,000 = $833,320**

**Verdict: Justified**

**Recommendation: Implement.** The upgrade is financially favorable and directly addresses the current gap in server-class detection while improving ransomware detection across the managed endpoint fleet.

---

# Control 6 — Dedicated Westside Clinic Firewall

**CIS Control Reference:** **CIS Control 12 — Network Infrastructure Management**

**Risk(s) Addressed:** Alternative ransomware entry path, VPN compromise, uncontrolled Westside-to-Central access.

The existing Netgear consumer router terminates the Westside site-to-site VPN to Central. The established remediation matrix budgets **$20,000** to replace it with enterprise-managed infrastructure.

## Annual Cost

For cost transparency, the existing $20,000 planning figure is decomposed as:

- Enterprise firewall/appliance and first-year subscription: **$12,000**
- Migration/configuration/testing: **50 hours × $100/hour = $5,000**
- First-year support/maintenance: **$3,000**

Therefore:

**Annual Cost = $12,000 + $5,000 + $3,000 = $20,000**

## ALE Impact

T15 rates Westside risk High but notes that no current kill chain or formal threat scenario explicitly begins there. Therefore, a large ALE reduction would not be defensible.

I assume replacement reduces enterprise ransomware frequency by only **5%**, reflecting removal of one credible alternate entry path.

Current ARO:

**0.30**

Residual ARO:

**0.30 × (1 − 0.05) = 0.285**

ALE before:

**$9,548,000 × 0.30 = $2,864,400**

ALE after:

**$9,548,000 × 0.285 = $2,721,180**

ALE Reduction:

**$2,864,400 − $2,721,180 = $143,220**

## Net Value

**$143,220 − $20,000 = $123,220**

**Verdict: Justified**

**Recommendation: Implement.** Even using only a 5% modeled reduction, the enterprise firewall produces positive financial value while closing an architectural trust path into Central.

---

# Control 7 — Outsourced 24/7 Security Operations Center

**CIS Control Reference:** **CIS Control 13 — Network Monitoring and Defense**

**Risk(s) Addressed:** Ransomware dwell time, after-hours attacks, alert triage, identity abuse, backup destruction.

This analysis treats the SOC as an **incremental control after Wazuh SIEM and EDR**, rather than giving it credit for benefits already assigned to those products.

Public MDR pricing demonstrates that 24/7 outsourced services are commonly priced per monitored endpoint; one published service lists an MDR response tier at £15 per endpoint/month.

## Annual Cost

Using a planning assumption of **$20 per endpoint/month** across the 529 modeled endpoint/server estate:

**529 endpoints × $20/month × 12 months**

**= $126,960/year**

Service integration/governance:

**$10,000/year**

Therefore:

**Annual Cost = $126,960 + $10,000**

**Annual Cost = $136,960**

This is a budget estimate, not a vendor quote.

## ALE Impact

After the modeled SIEM and EDR effects, residual enterprise ransomware ALE is:

**$2,864,400 × 65% × 70%**

**= $1,303,302**

I assume 24/7 human monitoring and response reduces this remaining ALE by another **15%** through faster off-hours triage and containment.

ALE Reduction:

**$1,303,302 × 15% = $195,495**

ALE after SOC:

**$1,303,302 − $195,495 = $1,107,807**

## Net Value

**$195,495 − $136,960 = $58,535**

**Verdict: Marginal**

**Recommendation: Defer.** The control has positive modeled value, but it consumes more than MedDefense's entire $120,000 annual budget by itself and provides much of its value only after SIEM and EDR telemetry exist. MedDefense should first build those lower-cost capabilities and use real alert volumes and response times to determine whether 24/7 outsourcing is financially necessary.

---

# Control 8 — Full Medical-Device Network Isolation with Dedicated Monitoring

**CIS Control Reference:** **CIS Control 12 — Network Infrastructure Management**  
**Supporting Control:** CIS Control 13 — Network Monitoring and Defense

**Risk(s) Addressed:** Medical-device denial of service, unauthorized device access, patient-safety compromise.

MedDefense has approximately 80 Philips patient monitors and 120 Alaris infusion pumps, plus MRI, nurse-call, and other connected clinical systems. The project concludes that these assets need segmentation, restricted management paths, monitoring, vendor coordination, and recovery procedures. 

The existing vulnerability roadmap already prices narrower controls at:

**Alaris remediation = $12,000**

**Philips remediation = $15,000**

Therefore:

**Targeted existing remediation = $12,000 + $15,000 = $27,000**

The proposed control here is substantially broader: complete medical-device isolation plus dedicated monitoring across the clinical fleet.

## Annual Cost

Planning estimate:

- Dedicated network/firewall/sensor infrastructure: **$25,000**
- Biomedical/vendor engineering and validation: **$30,000**
- Dedicated monitoring platform/sensors: **$20,000**
- Deployment and clinical validation labor: **$10,000**
- Annual maintenance/tuning: **$10,000**

Therefore:

**Annual Cost = $25,000 + $30,000 + $20,000 + $10,000 + $10,000**

**Annual Cost = $95,000**

## ALE Impact

Current medical-device ALE:

**$25,000 DoS ALE + $60,000 patient-safety ALE = $85,000/year**

Assume full isolation and monitoring reduce both event frequencies by **70%**.

Residual ALE:

**$85,000 × 30% = $25,500**

ALE Reduction:

**$85,000 − $25,500 = $59,500**

## Net Value

**$59,500 − $95,000 = −$35,500**

**Verdict: Not Justified as Proposed**

**Recommendation: Reject the $95,000 full architecture and implement the lower-cost targeted medical-device controls instead.** The current project already identifies approximately **$27,000** of targeted Alaris and Philips work; that approach is financially more defensible while still addressing default credentials and broad device reachability.

This verdict is financial, not clinical. Patient-safety risk may justify spending beyond pure ALE calculations if leadership determines the residual clinical risk is unacceptable.

---

# Cost-Benefit Summary

| Rank | Control | ALE Reduction | Annual Cost | Net Value | Verdict |
|---:|---|---:|---:|---:|---|
| **1** | **Network segmentation** | **$2,864,400 − $1,145,760 = $1,718,640** | **$35,000** | **$1,683,640** | **Justified** |
| **2** | **MFA — VPN/admin accounts** | **$2,864,400 − $1,432,200 = $1,432,200** | **$10,000** | **$1,422,200** | **Justified** |
| **3** | **Wazuh SIEM** | **$2,864,400 − $1,861,860 = $1,002,540** | **$21,000** | **$981,540** | **Justified** |
| **4** | **EDR upgrade** | **$2,864,400 − $2,005,080 = $859,320** | **$26,000** | **$833,320** | **Justified** |
| **5** | **Westside firewall** | **$2,864,400 − $2,721,180 = $143,220** | **$20,000** | **$123,220** | **Justified** |
| **6** | **Offsite immutable backup** | **$135,143 − $60,543 = $74,600** | **$8,000** | **$66,600** | **Justified** |
| **7** | **24/7 outsourced SOC** | **$1,303,302 − $1,107,807 = $195,495** | **$136,960** | **$58,535** | **Marginal** |
| **8** | **Full medical-device isolation/monitoring** | **$85,000 − $25,500 = $59,500** | **$95,000** | **−$35,500** | **Not Justified** |

# $120,000 Budget Decision

The six controls with the strongest combination of positive Net Value and feasible annual cost are:

1. Network segmentation — **$35,000**
2. MFA — **$10,000**
3. Wazuh SIEM — **$21,000**
4. EDR upgrade — **$26,000**
5. Westside firewall — **$20,000**
6. Offsite immutable backup — **$8,000**

Total:

**$35,000 + $10,000 + $21,000 + $26,000 + $20,000 + $8,000**

**= $120,000**

Therefore:

**Available budget = $120,000**

**Selected controls = $120,000**

**Remaining budget = $120,000 − $120,000 = $0**

The package mathematically fits the annual constraint exactly. It does, however, leave no contingency for implementation overruns, so management should either negotiate the estimates downward or authorize a small contingency outside the security-program ceiling.

The two controls excluded from the $120,000 package are:

**24/7 outsourced SOC:** **$136,960 > $120,000**, so it cannot fit within the annual budget even if nothing else is funded.

**Full medical-device isolation/monitoring:** **$95,000** is affordable in isolation, but its modeled risk reduction is only **$59,500**, producing:

**$59,500 − $95,000 = −$35,500**

and therefore failing the formal cost-benefit test.

MedDefense should instead fund the narrower medical-device remediation already documented in the vulnerability plan, where:

**Alaris $12,000 + Philips $15,000 = $27,000**

rather than committing $95,000 to the full architecture.

## Management Conclusion

The analysis demonstrates why controls should not be selected merely because they are technically desirable.

**Network segmentation, MFA, SIEM, EDR, Westside perimeter replacement, and immutable recovery all produce positive modeled financial value.** The strongest opportunities are segmentation and MFA because they attack the structural conditions that allow a single foothold or stolen password to become an enterprise incident.

The outsourced SOC is different. It provides useful additional resilience, but its economics are dependent on first establishing lower-cost telemetry and response capabilities. It should therefore be reconsidered after Wazuh and EDR generate enough operational data to measure alert volume, after-hours incidents, and response times.

The full $95,000 medical-device architecture fails the pure financial test, but this does not justify leaving medical devices exposed. The rational alternative is the already-scoped **$27,000 targeted remediation**, preserving the principle:

**Do not accept an expensive control simply because the underlying risk matters; find the lowest-cost control that reduces the risk to an acceptable level.**

Finally, the individual Net Values above should not be added into one portfolio ROI figure. Segmentation, MFA, SIEM, EDR, and the SOC all reduce overlapping portions of the same enterprise-ransomware ALE. Their values are useful for comparing controls, but summing them would count the same avoided loss multiple times.
