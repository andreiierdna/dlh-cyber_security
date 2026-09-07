# Threat Actor Taxonomy

## Report A

**Actor Type:** **Nation-State**

**Internal/External:** **External** — the compromise began through a zero-day vulnerability in the organization's VPN appliance, indicating intrusion from outside the pharmaceutical company rather than misuse of legitimate internal access.

**Resources:** **High** — the attacker possessed or obtained a zero-day exploit, deployed a custom remote-access tool, used encrypted DNS for covert command-and-control, and signed malware with a stolen code-signing certificate. These capabilities imply substantial financial and technical resources.

**Sophistication:** **High** — the actor maintained access for approximately 14 months while systematically stealing proprietary research data and using techniques specifically designed to evade detection.

**Primary Motivation:** **Espionage** — the target was Phase III clinical-trial information valued at approximately $2 billion in future revenue. The sustained, covert collection of strategically valuable pharmaceutical research is more consistent with intelligence acquisition than immediate financial extortion.

**Confidence Level:** **High** — the combination of zero-day exploitation, custom malware, stolen signing certificates, prolonged dwell time, and strategic R&D targeting strongly matches nation-state behavior.

---

## Report B

**Actor Type:** **Organized Crime**

**Internal/External:** **External** — initial access was obtained through a malicious email campaign impersonating a medical supplier.

**Resources:** **Medium** — the attackers conducted targeted phishing and coordinated data theft, ransomware deployment, and extortion, but relied on a known Adobe vulnerability and a commercially available RAT rather than custom malware or zero-days.

**Sophistication:** **Medium** — the operation demonstrates an organized attack chain: phishing, persistent access, patient-data exfiltration, network-wide ransomware deployment, and double extortion. However, the underlying tools were commercially available and the exploited vulnerability was already known.

**Primary Motivation:** **Financial gain** — the attackers demanded 40 Bitcoin, approximately $1.6 million, and used stolen patient data as additional leverage to obtain payment.

**Confidence Level:** **High** — ransomware deployment, cryptocurrency payment demands, data theft, and publication threats form a characteristic financially motivated organized-crime pattern.

---

## Report C

**Actor Type:** **Hacktivist**

**Internal/External:** **External** — the attackers compromised the hospital's public-facing content-management system through SQL injection.

**Resources:** **Low** — there is no evidence of expensive infrastructure, custom tooling, zero-days, or sustained access. A web-application vulnerability was sufficient to achieve the objective.

**Sophistication:** **Low** — the attackers used SQL injection to modify the website and deliberately stopped at the web server rather than attempting lateral movement or patient-data access.

**Primary Motivation:** **Philosophical or political beliefs** — the defacement explicitly protested the hospital's decision to close a free community health clinic and called for public demonstrations.

**Confidence Level:** **High** — the ideological message, activist-group branding, public defacement, absence of financial demands, and lack of interest in internal systems strongly identify hacktivist behavior.

---

## Report D

**Actor Type:** **Insider Threat**

**Internal/External:** **Internal** — the actor was a former privileged administrator who used knowledge and access obtained while employed. Although the destructive login occurred remotely from a home IP address after termination, the attack depended on an unauthorized VPN account created while the administrator was still an insider.

**Resources:** **Low** — no specialized malware, exploit development, or external criminal infrastructure was required. The attacker relied primarily on legitimate administrative knowledge and previously established credentials.

**Sophistication:** **Medium** — the administrator planned ahead by creating a secondary VPN account not tied to the normal directory and disabling database backups three days before termination. This demonstrates deliberate preparation and knowledge of recovery controls.

**Primary Motivation:** **Revenge** — the destructive action occurred shortly after a disciplinary termination, and the deliberate deletion of production claims data combined with prior backup sabotage strongly indicates retaliation.

**Confidence Level:** **High** — timing, privileged knowledge, pre-positioned access, deliberate backup disruption, and use of the former administrator's home IP provide unusually strong behavioral attribution.

---

## Report E

**Actor Type:** **Unskilled Attacker**

**Internal/External:** **External** — an automated exploit campaign targeted an exposed remote-management vulnerability across hundreds of unrelated organizations.

**Resources:** **Low** — the attackers used a publicly available cryptocurrency miner and automated exploitation of a vulnerability disclosed six months earlier.

**Sophistication:** **Low** — there was no lateral movement, patient-data targeting, persistent backdoor deployment, or customized malware. The attack simply exploited vulnerable systems at scale and installed commodity mining software.

**Primary Motivation:** **Financial gain** — compromised workstation resources were used to mine Monero for the attacker's wallet.

**Confidence Level:** **High** — the same wallet was associated with more than 300 organizations, strongly indicating indiscriminate automated exploitation rather than targeted intrusion.

---

## Report F

**Actor Type:** **Shadow IT**

**Internal/External:** **Internal** — the security condition originated when an employee connected a personally controlled Raspberry Pi to the medical-device network without authorization. A separate external attacker subsequently exploited that device, but the defining actor behavior for this classification is the employee's introduction of unmanaged technology into the hospital environment.

**Resources:** **Low** — the Raspberry Pi used commodity hardware, an outdated operating system, default credentials, and an inadvertently exposed port.

**Sophistication:** **Low** — the employee's configuration demonstrated weak security practices rather than advanced capability. The downstream attacker also required little sophistication because the device could be accessed using default `pi/raspberry` credentials.

**Primary Motivation:** **Ethical motivations** — this is the closest available Security+ motivation category, because the employee stated that the system was intended to monitor network performance for a personal project rather than for financial gain, revenge, disruption, or espionage. The source does not establish a malicious motive, and none of the listed motivations precisely captures convenience-driven personal experimentation.

**Confidence Level:** **High** for the **shadow IT classification**, because the employee intentionally introduced an unauthorized personal device into the medical network. Confidence in the motivation classification is **Low**, because the Security+ motivation list does not contain an exact category for benign but unauthorized experimentation.

The report also contains a **secondary threat actor**: the external attacker who discovered the exposed Pi, used its default credentials, and pivoted into the nurse-call environment. That actor would most plausibly be classified as an **unskilled/opportunistic attacker** based on the available evidence.

---

# Report G

**Actor Type:** **Could be Insider Threat or Organized Crime — provisional classification: Organized Crime**

**Internal/External:** **Could be either** — all access occurred through a legitimate physician account, which could indicate malicious internal use, but the physician was on extended leave and documented as being outside the country. The same observations are also consistent with an external attacker using stolen credentials or a hijacked authenticated session.

**Resources:** **Medium** — the actor maintained access for six weeks and selectively downloaded 3,200 records associated with high-value insurance plans. This indicates deliberate targeting and operational discipline, but there is no evidence of custom malware, zero-day exploitation, or expensive infrastructure.

**Sophistication:** **Medium** — the activity was sustained, occurred exclusively during off-hours, and used legitimate credentials in a manner that could blend with normal application traffic. The evidence does not reveal how the credentials were acquired.

**Primary Motivation:** **Data exfiltration** — downloading thousands of unrelated patient records is the only motive directly established by the evidence. Concentration on high-value insurance plans suggests possible downstream financial fraud, but no ransom demand, sale, or other monetization has yet been observed.

**Confidence Level:** **Low** — the behavior clearly establishes credential misuse and deliberate data theft, but it does not establish who controlled the account or how access was obtained.

### Why Report G Is Ambiguous

At least three plausible explanations fit the observed activity:

1. **Malicious insider threat.** Another employee could have obtained or known the physician's credentials and used them to access records for financial purposes. The selection of patients with high-value insurance plans could indicate someone familiar with healthcare data and fraud opportunities.

2. **Organized crime using stolen credentials.** An external criminal could have acquired the physician's password through phishing, credential theft, malware, or an access broker and deliberately used a valid account to avoid triggering exploit-based security controls.

3. **Unskilled or opportunistic external attacker.** If the physician reused credentials that had appeared in a breach, an attacker could have gained access through credential stuffing. This explanation is less persuasive because six weeks of selective access to high-value insurance records suggests more purposeful activity than ordinary bulk credential abuse.

The physician's absence is important but does **not** prove external compromise. A legitimate physician account can be abused by another insider just as easily as by an external attacker.

### Evidence Required to Distinguish the Actor Types

The most useful additional evidence would be:

* **Source-IP attribution:** ISP ownership, geolocation, VPN/proxy use, and whether the IP corresponds to another employee, third party, hosting provider, or anonymization service.
* **Authentication telemetry:** MFA events, failed logins, password-reset history, impossible-travel alerts, VPN/SSO logs, and evidence of stolen session tokens.
* **Device fingerprinting:** browser identifiers, operating system, endpoint ID, user-agent information, and comparison with the physician's normal devices.
* **Endpoint forensics:** evidence of credential-stealing malware or session-cookie theft on the physician's laptop or other systems.
* **EHR audit records:** search terms, navigation patterns, record-selection logic, export methods, and whether the behavior resembles normal clinical usage.
* **Internal-access investigation:** whether other employees had access to the physician's credentials or workstation and whether the source IP can be associated with staff or contractors.
* **Post-exfiltration evidence:** appearance of the records in insurance-fraud activity, criminal marketplaces, extortion communications, or other monetization channels.

Until that evidence is obtained, assigning a named group or asserting that the activity was definitively internal or external would exceed what the report supports.

---

## Report H

**Actor Type:** **Organized Crime**

**Internal/External:** **External** — unauthorized API access originated from a Tor exit node, followed by an extortion demand from an unknown external sender.

**Resources:** **Medium** — the attacker successfully identified and exploited a broken authentication endpoint, extracted 2,000 valid patient records, used Tor to obscure origin, and converted the compromise into an extortion attempt. There is no evidence of custom malware or zero-day research.

**Sophistication:** **Medium** — exploiting a vulnerable API, verifying exfiltrated data, using anonymization infrastructure, and presenting a credible proof sample demonstrate competence. However, the underlying vulnerability had already been reported internally three months earlier and was not a newly discovered zero-day.

**Primary Motivation:** **Blackmail** — the attacker explicitly demanded $50,000 in cryptocurrency in exchange for withholding vulnerability information and stolen patient records.

**Confidence Level:** **Medium** — the financial extortion behavior is clear, but the report does not establish whether the attacker belongs to an organized criminal group or is an independent criminal. Organized crime is the best fit among the six required categories because the attack combined unauthorized access, data theft, cryptocurrency extortion, and threatened disclosure.

---

# Classification Summary

| Report | Actor Type                    | Position        | Resources | Sophistication | Primary Motivation              | Confidence                   |
| ------ | ----------------------------- | --------------- | --------- | -------------- | ------------------------------- | ---------------------------- |
| **A**  | Nation-State                  | External        | High      | High           | Espionage                       | High                         |
| **B**  | Organized Crime               | External        | Medium    | Medium         | Financial gain                  | High                         |
| **C**  | Hacktivist                    | External        | Low       | Low            | Philosophical/political beliefs | High                         |
| **D**  | Insider Threat                | Internal        | Low       | Medium         | Revenge                         | High                         |
| **E**  | Unskilled Attacker            | External        | Low       | Low            | Financial gain                  | High                         |
| **F**  | Shadow IT                     | Internal        | Low       | Low            | Ethical motivations*            | High actor-type / Low motive |
| **G**  | Organized Crime — provisional | Could be either | Medium    | Medium         | Data exfiltration               | Low                          |
| **H**  | Organized Crime               | External        | Medium    | Medium         | Blackmail                       | Medium                       |

*For Report F, the required motivation framework does not contain a precise category for benign, unauthorized personal experimentation; **ethical motivations** is therefore the nearest available category rather than a definitive description.
