# Task 2 – The CVSS Deconstruction

# Exercise 1 – Deconstruction

## Finding 001: CVE-2021-44790

The scan identified **Finding 001** on `billing-srv-01` (`10.10.2.15`), affecting Apache HTTP Server through the `mod_lua` multipart parser. The scan reports a Base Score of **9.8 Critical** with the following CVSS v3.1 vector:

**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H**

The authenticated scan confirmed that `mod_lua` is loaded and states that a crafted request can potentially result in remote code execution without authentication. NVD independently records the same **9.8 Critical** score and vector for CVE-2021-44790.

## CVSS Component Deconstruction

| Component    | What the abbreviation means                     | Meaning of the selected value                                                                                                   | Other possible values and score effect                                                                                                                                                                                                       | Why this value applies                                                                                                                                                                                                                                                            |
| ------------ | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CVSS:3.1** | Common Vulnerability Scoring System version 3.1 | Identifies the CVSS specification used to interpret the vector.                                                                 | It is not itself a scored metric.                                                                                                                                                                                                            | Both the scan and NVD use CVSS v3.1.                                                                                                                                                                                                                                              |
| **AV:N**     | **Attack Vector: Network**                      | The vulnerable component can be attacked through the network stack without the attacker first obtaining local system execution. | Other values are Adjacent (A), Local (L), and Physical (P). Restricting the attacker to a closer position progressively reduces exploitability.                                                                                              | CVE-2021-44790 is triggered through a specially crafted HTTP request body processed by Apache. NVD therefore assigns Network.                                                                                                                                                     |
| **AC:L**     | **Attack Complexity: Low**                      | Successful exploitation does not depend on unusual circumstances or conditions outside the attacker's control.                  | The alternative is High (H). If only AC changed to High, the Base Score would fall from **9.8 to 8.1**.                                                                                                                                      | NVD assigns AC:L. The fact that `mod_lua` must be enabled does not itself justify AC:H; CVSS guidance states that a vulnerability requiring a vulnerable configuration is scored assuming that configuration exists. The scan additionally confirms `mod_lua` is actually loaded. |
| **PR:N**     | **Privileges Required: None**                   | The attacker does not need an authenticated account or other privileges before exploitation.                                    | Alternatives are Low (L) and High (H). Holding everything else constant, PR:L produces **8.8** and PR:H approximately **7.2**.                                                                                                               | The scan explicitly describes possible remote code execution without authentication.                                                                                                                                                                                              |
| **UI:N**     | **User Interaction: None**                      | Exploitation does not require another user to perform an action such as clicking a link or opening a file.                      | The alternative is Required (R). Changing only UI to Required reduces the score to approximately **8.8**.                                                                                                                                    | The attacker communicates directly with the vulnerable Apache request-processing functionality; no victim action is required.                                                                                                                                                     |
| **S:U**      | **Scope: Unchanged**                            | The vulnerable component and the directly affected resources remain under the same security authority.                          | The alternative is Changed (C). For this particular metric combination, changing Scope alone to Changed results in the Base Score reaching **10.0** because CVSS applies a different impact calculation when a security boundary is crossed. | NVD assigns Scope Unchanged for this CVE.                                                                                                                                                                                                                                         |
| **C:H**      | **Confidentiality Impact: High**                | Successful exploitation can cause a severe or complete loss of confidentiality within the affected component.                   | Low (L) means limited disclosure; None (N) means no confidentiality impact. In this vector, changing C to Low gives approximately **9.4**, while None gives approximately **9.1**.                                                           | Potential arbitrary code execution provides a basis for extensive access to information available to the compromised service or system.                                                                                                                                           |
| **I:H**      | **Integrity Impact: High**                      | Successful exploitation can cause a severe or complete loss of integrity.                                                       | Low (L) represents limited modification and None (N) means no integrity impact. Changing I to Low gives approximately **9.4**; None gives approximately **9.1**.                                                                             | Arbitrary code execution can permit unauthorized modification of data, files, application behavior, or configuration.                                                                                                                                                             |
| **A:H**      | **Availability Impact: High**                   | Successful exploitation can cause a severe or complete loss of availability.                                                    | Low (L) means reduced or intermittent performance; None (N) means no availability impact. Changing A to Low gives approximately **9.4**; None gives approximately **9.1**.                                                                   | Memory corruption and potential code execution can crash or take control of the affected Apache service and potentially disrupt the host.                                                                                                                                         |

The valid CVSS v3.1 Base metric choices are AV `[N,A,L,P]`, AC `[L,H]`, PR `[N,L,H]`, UI `[N,R]`, Scope `[U,C]`, and High/Low/None for each CIA impact metric.

---

## Changing Attack Vector from Network to Local

The exercise requires changing only:

**AV:N → AV:L**

The resulting vector is:

**CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H**

Entering this modified vector into the NIST/NVD CVSS v3.1 Calculator produces:

**Base Score: 8.4 – High**

The original vector scores **9.8 – Critical**.

The reason is that changing Attack Vector does not change the consequences of successful exploitation. Confidentiality, Integrity, and Availability remain High, so the Impact Subscore remains approximately **5.9**. What changes is exploitability:

| Measure                 |             AV:N |         AV:L |
| ----------------------- | ---------------: | -----------: |
| Impact Subscore         |              5.9 |          5.9 |
| Exploitability Subscore |              3.9 |          2.5 |
| Base Score              | **9.8 Critical** | **8.4 High** |

CVSS assigns Network an Attack Vector weight of **0.85**, while Local has a lower weight of **0.55**. The specification explains that a vulnerability exploitable across a network has a larger potential attacker population than one requiring local execution capability, and therefore receives a higher Base Score.

This change is analytically significant for MedDefense. With the actual AV:N condition, the attacker can potentially reach the vulnerable Apache service without first compromising `billing-srv-01`. Under the hypothetical AV:L condition, an attacker would first require some form of local read/write/execute capability. That additional prerequisite reduces exploitability and therefore changes the severity classification from **Critical to High**.

---

# Exercise 2 – Construction

The hypothetical vulnerability has the following characteristics:

| Characteristic                                           | CVSS metric selected | Reason                                                                                        |
| -------------------------------------------------------- | -------------------- | --------------------------------------------------------------------------------------------- |
| Exploitable only from the local network                  | **AV:A**             | Interpreted as requiring protocol-level access from a logically adjacent local network.       |
| Exploitation is complex and requires specific conditions | **AC:H**             | Successful exploitation depends on particular circumstances beyond ordinary attacker control. |
| Attacker requires low-level privileges                   | **PR:L**             | The attacker must already possess limited privileges.                                         |
| No user interaction                                      | **UI:N**             | No separate user needs to perform an action.                                                  |
| Scope remains within the targeted system                 | **S:U**              | Exploitation does not cross a security-authority boundary.                                    |
| Complete confidentiality compromise                      | **C:H**              | Confidentiality impact is High.                                                               |
| No integrity effect                                      | **I:N**              | Integrity is not affected.                                                                    |
| No availability effect                                   | **A:N**              | Availability is not affected.                                                                 |

The manually constructed vector is therefore:

**CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N**

Entering this vector into the CVSS v3.1 calculator produces:

**Base Score: 4.8**
**Severity Rating: Medium**

CVSS v3.1 defines **4.0–6.9 as Medium severity**.

## Important Attack Vector Distinction

The phrase **“local network”** requires careful interpretation under CVSS.

Adjacent (AV:A) is correct only where exploitation requires protocol-level logical adjacency—for example, the same local IP subnet or another specifically limited administrative network domain. FIRST explicitly states that if a vulnerability can be exploited across a routed corporate intranet, the correct rating may still be **Network (AV:N)** even though the vulnerable system is not Internet-accessible.

Therefore, this exercise uses **AV:A** because the stated condition is interpreted as genuine local-network adjacency. If “local network” instead meant that any host anywhere on MedDefense's routed internal network could exploit the vulnerability, AV:N would be more appropriate.

## Cross-Reference Applicability

Exercise 2 describes a **hypothetical vulnerability** and does not identify a MedDefense host or scan finding. Assigning an AST identifier, threat actor, or GAP identifier would therefore create evidence that does not exist in the supplied projects. No MedDefense cross-reference is assigned to this hypothetical example.

---

# Exercise 3 – Comparison

## Requirement Conflict in the Scan Report

The instructions request:

1. one finding with a CVSS score **above 9.0**; and
2. one finding with a CVSS score **between 5.0 and 7.0**.

The supplied scan does not contain a scored finding within the requested **5.0–7.0** interval.

Examples of scored findings in the report include:

Finding 001 at **9.8**, Finding 002 at **7.8**, Finding 005 at **7.5**, Finding 010 at **7.5**, Finding 020 at **9.8**, and Finding 031 at **9.8**.
Fabricating a 5.0–7.0 finding would violate the project's evidence requirement. Accordingly, **Finding 010 at 7.5 is used as the closest fully documented fallback**. It is particularly appropriate because, unlike some other possible fallback findings, it has direct cross-references to a documented asset, threat actor, and prioritized gap.

---

## Finding 001 versus Finding 010

### Finding 001

**CVE-2021-44790 – Apache HTTP Server mod_lua Buffer Overflow**

Asset: `billing-srv-01`
Vector:

**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H**

Score:

**9.8 Critical**

### Finding 010

**CVE-2020-25165 – BD Alaris Infusion Pump Known Vulnerability**

Affected hosts: multiple BD Alaris pumps (`10.10.3.40–46`)
Vector:

**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H**

Score:

**7.5 High**

The scan states that the vulnerability can permit an attacker to cause denial of service and additionally records that seven of seven tested pumps still use default management credentials.

## Side-by-Side CVSS Comparison

| CVSS metric         | Finding 001      | Finding 010  | Effect on difference     |
| ------------------- | ---------------- | ------------ | ------------------------ |
| Attack Vector       | N                | N            | Identical                |
| Attack Complexity   | L                | L            | Identical                |
| Privileges Required | N                | N            | Identical                |
| User Interaction    | N                | N            | Identical                |
| Scope               | U                | U            | Identical                |
| Confidentiality     | **H**            | **N**        | Major difference         |
| Integrity           | **H**            | **N**        | Major difference         |
| Availability        | H                | H            | Identical                |
| **Base Score**      | **9.8 Critical** | **7.5 High** | **2.3-point difference** |

This comparison controls for the exploitability metrics especially well. Both findings use:

**AV:N/AC:L/PR:N/UI:N/S:U**

Therefore, both have essentially the same Base Exploitability Subscore of approximately **3.9**.

The difference is in impact.

Finding 001 has:

**C:H/I:H/A:H**

Finding 010 has:

**C:N/I:N/A:H**

Finding 001 therefore has an Impact Subscore of approximately **5.9**, whereas Finding 010 has an Impact Subscore of approximately **3.6**. With the same exploitability characteristics, the larger CIA impact produces the 9.8 score.

### Which Components Have the Biggest Impact?

For these two findings, the components responsible for the score difference are specifically:

**Confidentiality and Integrity.**

Both are **High** for Finding 001 and **None** for Finding 010. Availability is High for both, so Availability does not explain their score difference.

This is an important illustration of CVSS as a decision tool. Two vulnerabilities can both be network exploitable, low complexity, unauthenticated, and require no user interaction, yet receive materially different scores because the consequences of successful exploitation differ.

Finding 001 models a compromise of all three security objectives:

**Confidentiality + Integrity + Availability**

Finding 010 models primarily:

**Availability**

As a result, Finding 001 receives **9.8 Critical**, while Finding 010 receives **7.5 High**.

---

## MedDefense Cross-Reference – Finding 001

### Asset

Finding 001 directly affects:

**AST-004 – billing-srv-01**

and places associated assets at risk:

**AST-019 – Billing/claims application**
**AST-020 – Billing database**

The registry records prior ransomware and cryptomining compromise of the same host and identifies the billing database as containing billing, claims, and patient financial information.

### Threat Actors

The strongest direct match is:

**Threat Actor 6 – Unskilled/Opportunistic Attacker**

The matrix identifies automated known-vulnerability exploitation as this actor's preferred technique and specifically identifies `billing-srv-01` as MedDefense's strongest demonstrated example.

A second relevant actor is:

**Threat Actor 1 – Ransomware Groups (Organized Crime)**

The ransomware profile explicitly records the prior compromise of `billing-srv-01` and includes GAP-008 among the conditions increasing MedDefense's exposure.

### Gap

**GAP-008 – Billing Server Lacks Server Malware Protection and Effective Egress Restriction**

The gap affects AST-004, AST-019, and AST-020 and states that server-capable endpoint detection and restrictive outbound controls are missing. It also records Restricted billing and patient financial information as the data at risk.

### Analysis

The CVSS score of 9.8 describes the technical characteristics of CVE-2021-44790, but the cross-reference explains why it matters specifically to MedDefense. The vulnerability is remotely reachable, low complexity, unauthenticated, requires no user interaction, and can affect confidentiality, integrity, and availability. It is also deployed on **AST-004**, a billing server with a demonstrated malware-compromise history, associated with Restricted financial information, and subject to **GAP-008**. The Threat Actor Matrix independently identifies automated exploitation against the billing server as a credible MedDefense scenario.

The result is therefore more actionable than stating only that “9.8 is Critical.” The vulnerability aligns simultaneously with a vulnerable asset, a demonstrated threat pathway, and a documented control deficiency.

---

# MedDefense Cross-Reference – Finding 010

### Asset

Finding 010 affects:

**AST-037 – BD Alaris infusion-pump fleet**

The Asset Registry identifies this fleet as supporting **medication infusion and dosage updates**, running firmware version 12.1.2, and operating without enforced VLAN separation. Management interfaces are reachable throughout the internal network.

### Gap

The directly applicable gap is:

**GAP-002 – Medical IoT Is Not Segmented, Monitored, or Recoverable**

GAP-002 explicitly includes **AST-037 BD Alaris infusion-pump fleet**. It states that management interfaces remain broadly reachable and identifies missing preventive, detective, and corrective controls, including enforced medical-device VLANs, default-deny internal access controls, behavioral monitoring, and documented recovery procedures. The gap is rated **Critical** because manipulation or disruption of clinical devices can affect bedside treatment.

### Threat Actor

The applicable prior-project external actor is:

**Threat Actor 1 – Ransomware Groups (Organized Crime)**

The Threat Actor Matrix specifically identifies **GAP-002 poor medical-device segmentation** as a condition that expands the blast radius of ransomware activity.

This mapping should be interpreted carefully. The matrix does **not** state that ransomware groups specifically prefer CVE-2020-25165. Rather, it establishes that ransomware operators are a credible MedDefense threat and that inadequate medical-device segmentation increases what such an attacker could reach after obtaining an internal foothold.

### Analysis

Finding 010 is therefore more significant than the 7.5 number alone suggests. CVSS correctly assigns no Confidentiality or Integrity impact to the supplied vector, which keeps its Base Score below Finding 001. However, MedDefense's own Gap Analysis classifies the surrounding Medical IoT environment as **Critical** because disruption of infusion pumps can affect clinical treatment.

This demonstrates an important limitation of using Base CVSS as the sole prioritization mechanism. **CVSS Base Score measures intrinsic vulnerability severity; it does not replace organizational asset criticality, threat likelihood, or environmental control analysis.**

Finding 001 has the higher technical Base Score because exploitation can compromise confidentiality, integrity, and availability. Finding 010 has the lower Base Score because the supplied vector represents availability impact only. Nevertheless, Finding 010 exists on **AST-037**, a clinically significant infusion-pump fleet operating under **GAP-002**, where insufficient network containment increases the consequences of an internal compromise.

---

# Final Assessment

The exercises demonstrate three distinct uses of CVSS.

**Deconstruction** shows why Finding 001 reaches 9.8: it combines remote network access, low complexity, no privileges, no user interaction, and High impact across confidentiality, integrity, and availability.

**Construction** shows how a set of vulnerability characteristics is translated systematically into a vector. The hypothetical case becomes:

**CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N = 4.8 Medium**

**Comparison** shows that score differences can be traced to individual metrics rather than treated as unexplained numbers. Findings 001 and 010 have identical exploitability components, but Finding 001 adds High Confidentiality and Integrity impacts. Those two components explain the movement from **7.5 to 9.8**.

Most importantly, the MedDefense cross-reference demonstrates why CVSS must be combined with organizational context. Finding 001 affects **AST-004/AST-019/AST-020**, aligns with **Threat Actor 6 – Unskilled/Opportunistic Attacker** and **Threat Actor 1 – Ransomware Groups**, and intersects directly with **GAP-008**. Finding 010 affects **AST-037**, exists within **GAP-002**, and sits within the broader ransomware blast-radius scenario documented in the Threat Actor Matrix.

Accordingly, CVSS provides the technical severity measurement, while the Asset Registry, Threat Actor Matrix, and Gap Analysis explain the vulnerability's **MedDefense-specific exposure and operational significance**.
