# Threat Analysis: Healthcare Mobile Application

**Prepared for:** Executive Security Review
**System:** Patient-facing mobile app (iOS/Android) with REST API backend, cloud-hosted database, and hospital system integration
**Scope:** Medical records viewing, appointment scheduling, provider messaging, prescription refills

---

## 1. Critical Asset Identification

**Most critical asset: Patient Health Information (PHI) stored in the cloud database and transmitted via the API.**

Applying the CIA Triad:

- **Confidentiality:** PHI is the most regulated data type under HIPAA. Exposure of diagnoses, medications, or mental health notes causes irreversible harm (discrimination, blackmail, identity theft) and triggers mandatory breach reporting.
- **Integrity:** Corrupted prescription or allergy data can directly cause patient harm (e.g., a tampered dosage record leading to overdose). Integrity failures here are safety failures, not just data failures.
- **Availability:** During emergencies, providers need immediate record access. Downtime during a clinical encounter can delay treatment decisions, though this is generally recoverable via downtime procedures, unlike confidentiality or integrity loss.

**Conclusion:** Confidentiality and integrity carry higher weighted risk than availability because their failure modes are irreversible or life-threatening, whereas availability failures are typically mitigated by fallback clinical workflows (paper charts, phone calls).

---

## 2. STRIDE Analysis — "Message Healthcare Providers" Feature

| STRIDE Category | Threat | Attack Scenario |
|---|---|---|
| **Spoofing** | Attacker impersonates a provider | An attacker compromises a provider's session token via a phishing link and sends messages to patients pretending to be their doctor, instructing them to stop a medication. |
| **Tampering** | Message content altered in transit or at rest | A man-in-the-middle attacker on public Wi-Fi intercepts an unencrypted API call and modifies a prescription refill request before it reaches the pharmacy system. |
| **Repudiation** | Provider denies sending a harmful instruction | A provider sends an incorrect dosage instruction, then later denies sending it because the system lacks message signing or immutable audit logs. |
| **Information Disclosure** | Message contents leaked to unauthorized parties | An Insecure Direct Object Reference (IDOR) in the messaging API (`/messages/{id}`) allows a patient to increment the ID and read other patients' conversations with providers. |
| **Denial of Service** | Messaging feature flooded to block critical communication | An attacker scripts thousands of message-send requests, exhausting API rate limits and preventing a patient from reaching a provider during a medical emergency. |
| **Elevation of Privilege** | Patient account gains provider-level messaging rights | A broken access control flaw lets a patient account call the provider-only "broadcast" endpoint, sending unauthorized mass messages to other patients. |

### Detailed Threat: Spoofing a Healthcare Provider

- **Description:** An attacker gains control of a provider's authentication token (via phishing, session hijacking, or credential stuffing) and uses it to send messages that appear to originate from a trusted clinician.
- **Attack Scenario:** Attacker sends a phishing email mimicking the hospital's SSO login page. A provider enters credentials; the attacker captures the session cookie and replays it against the messaging API to send a fraudulent message to a patient claiming a lab result is normal when it is not.
- **Impact:** High — patient safety harm, loss of trust, potential litigation, regulatory penalties under HIPAA.
- **Likelihood:** Medium — phishing is common, but requires bypassing MFA if enabled.
- **Mitigation:** Enforce hardware-backed MFA (FIDO2/WebAuthn) for all provider accounts, bind sessions to device fingerprints, and implement short-lived tokens (15-minute expiry) with re-authentication for sensitive actions.

### DREAD Score — Provider Spoofing

**Formula:** `DREAD = (Damage + Reproducibility + Exploitability + Affected Users + Discoverability) / 5`, each scored 1–10.

| Factor | Score | Reasoning |
|---|---|---|
| Damage | 9 | Patient safety directly impacted; false medical guidance |
| Reproducibility | 6 | Requires successful phishing, not guaranteed every attempt |
| Exploitability | 5 | Needs social engineering skill, not purely technical |
| Affected Users | 4 | Typically one patient per compromised provider account |
| Discoverability | 6 | Phishing kits targeting healthcare SSO are publicly available |

**DREAD Total = (9 + 6 + 5 + 4 + 6) / 5 = 6.0 → High Risk**

### DREAD Score — Message IDOR (Information Disclosure)

| Factor | Score | Reasoning |
|---|---|---|
| Damage | 8 | Exposes PHI across multiple patients, HIPAA breach |
| Reproducibility | 9 | Trivial to reproduce once discovered (sequential IDs) |
| Exploitability | 8 | Requires only basic API tooling (Postman/Burp) |
| Affected Users | 9 | Potentially every patient in the database |
| Discoverability | 7 | Sequential IDs are commonly probed by testers/attackers |

**DREAD Total = (8 + 9 + 8 + 9 + 7) / 5 = 8.2 → Critical Risk**

### Detailed Threat: Message Tampering in Transit

- **Description:** An attacker positioned between the mobile client and the API (e.g., on unsecured public Wi-Fi or via a malicious proxy) intercepts and modifies message or prescription-request payloads before they reach the backend.
- **Attack Scenario:** A patient uses a coffee shop Wi-Fi network with an attacker-controlled rogue access point. The app's TLS certificate pinning is missing, so the attacker performs a TLS downgrade and edits a prescription refill request to change the medication dosage field before forwarding it.
- **Impact:** High — incorrect medication dispensing poses direct patient safety risk and creates significant liability exposure for the hospital.
- **Likelihood:** Low-Medium — requires active network positioning and a missing certificate-pinning control, which is a specific implementation gap.
- **Mitigation:** Implement certificate pinning in the mobile client, enforce TLS 1.2+ with strict cipher suites, and add server-side integrity checks (HMAC signatures) on prescription-related payloads so tampered requests are rejected before processing.

### DREAD Score — Message Tampering

| Factor | Score | Reasoning |
|---|---|---|
| Damage | 8 | Incorrect dosage instructions risk direct patient harm |
| Reproducibility | 4 | Requires active MITM positioning, not always available |
| Exploitability | 5 | Needs specialized tooling (rogue AP, TLS-strip proxy) |
| Affected Users | 3 | Limited to patients on the specific compromised network |
| Discoverability | 4 | Missing cert pinning is not obvious without app analysis |

**DREAD Total = (8 + 4 + 5 + 3 + 4) / 5 = 4.8 → Medium Risk**

---

## 3. Prioritized Security Controls for Patient Data Protection

Given typical constraints (limited security budget, small engineering team, 6–12 month roadmap), controls are prioritized by risk reduction per dollar and implementation complexity:

1. **Strong Authentication & MFA (Priority 1)**
   Enforce MFA for all provider and admin accounts, and risk-based step-up authentication for patients accessing sensitive records. This directly closes the highest-DREAD threat (spoofing) at relatively low cost using existing identity providers (Okta, Azure AD B2C).

2. **End-to-End Encryption of PHI in Transit and at Rest (Priority 2)**
   TLS 1.2+ for all API traffic and AES-256 encryption for the database, with field-level encryption for highly sensitive fields (diagnoses, mental health notes). Mitigates tampering and disclosure with mature, well-documented libraries — low engineering overhead relative to risk reduction.

3. **Object-Level Access Control (Authorization Hardening) (Priority 3)**
   Fix IDOR-class vulnerabilities by enforcing server-side ownership checks on every record and message ID, not relying on client-supplied identifiers. Addresses the Critical (8.2) DREAD score found above; this is a code-level fix, not a purchased product, making it high-impact and low-cost.

4. **Immutable Audit Logging (Priority 4)**
   Log all access to PHI and all provider messages in a write-once, tamper-evident store (e.g., append-only log with cryptographic hash chaining). Resolves repudiation threats and satisfies HIPAA's audit control requirement (45 CFR §164.312(b)). Moderate cost due to storage and log-review tooling.

5. **API Rate Limiting and Anomaly Detection (Priority 5)**
   Apply per-user and per-IP rate limits on the messaging and records APIs, paired with basic anomaly alerts (e.g., sudden spike in record access). Mitigates DoS and mass-scraping scenarios. Lower priority than the above because its failure mode (temporary unavailability) is less severe than confidentiality or integrity loss.

**Rationale for ordering:** Controls 1–3 address vulnerabilities with the highest DREAD scores (spoofing and IDOR) and are foundational — later controls are less effective if authentication and authorization are broken. Controls 4–5 add defense-in-depth and regulatory compliance but address lower-likelihood or lower-impact scenarios, making them appropriate for a phase-two rollout once budget allows.

---

## Glossary

- **PHI:** Protected Health Information, as defined under HIPAA.
- **IDOR:** Insecure Direct Object Reference, a broken access control vulnerability.
- **DREAD:** A risk-scoring model (Damage, Reproducibility, Exploitability, Affected Users, Discoverability).
- **STRIDE:** A threat classification model (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
- **CIA Triad:** Confidentiality, Integrity, and Availability — the three core properties of information security.

## Real-World Constraints Considered

- **Budget:** Prioritization favors code-level fixes (authorization, rate limiting) over expensive third-party security products, deferring costlier controls like dedicated SIEM tooling to a later phase.
- **Team size:** A small engineering team cannot implement all controls simultaneously; the ordering above assumes a phased rollout over two to three sprints per control.
- **Regulatory deadlines:** HIPAA audit control requirements make immutable logging non-negotiable within the fiscal year, even though it is ranked fourth by pure risk reduction.
- **User experience:** MFA and step-up authentication are scoped to sensitive actions only, to avoid excessive friction that could reduce patient app adoption.

## Risk Register Summary

| Threat | STRIDE Category | DREAD Score | Risk Level |
|---|---|---|---|
| Provider Identity Spoofing | Spoofing | 6.0 | High |
| Message/Prescription Tampering | Tampering | 4.8 | Medium |
| Messaging IDOR Disclosure | Information Disclosure | 8.2 | Critical |

## Summary

The highest-risk exposure in this system is unauthorized access to PHI via broken authorization (DREAD 8.2) and provider identity spoofing (DREAD 6.0). Remediation should begin immediately with authorization fixes (low cost, high impact) in parallel with an MFA rollout, followed by encryption hardening and audit logging within the current fiscal quarter to meet HIPAA compliance deadlines.

Overall, the system's risk profile is driven primarily by authorization and authentication weaknesses rather than exotic attack techniques, meaning the highest-value investment for stakeholders is disciplined engineering hygiene rather than new security tooling purchases.
