# Task 13 — The Web Exposure

Web vulnerabilities must be evaluated in context. An Internet-facing patient portal can be attacked directly by external actors, whereas an internal NAS or EHR application normally requires an attacker to obtain an internal foothold first. MedDefense's flat internal network reduces that distinction, however, because once one internal system is compromised, management and application interfaces that would normally be protected by segmentation become reachable attack targets.

## Host 1 — Patient Portal / Public Web Server

**Host:** `web-srv-01 — 10.10.2.50`

**Exposure:** **Internet-facing.**

The Asset Registry identifies `web-srv-01` as hosting MedDefense's public website and patient portal. The patient portal provides patients with access to health information and is documented as Internet-facing.

**Findings:**

**Finding 005 — TLS 1.0 Enabled.**
The server supports TLS 1.0 in addition to TLS 1.2. The scan associates the legacy protocol with BEAST, POODLE and related attacks. Because the server hosts a patient portal transmitting PHI, weaknesses affecting transport confidentiality are more significant than they would be on a public-information-only site.

**Finding 012 — Missing HTTP Security Headers.**
The server is missing `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, and `X-XSS-Protection`. The scan correctly characterizes these as defense-in-depth controls rather than standalone application compromises.

**Finding 013 — TLS Certificate Expiration Warning.**
The patient-portal certificate expires in 23 days and automatic renewal is not configured. This is principally an availability and trust issue: expiration could cause browser warnings or prevent patients from using the portal normally.

**Finding 021 — HTTP TRACE Enabled.**
The server accepts the TRACE method. The scan states that TRACE is low risk by itself but can contribute to Cross-Site Tracing attacks when another weakness such as XSS exists.

### Combined Risk

**High exposure, but Medium-to-High aggregate vulnerability risk.**

The important distinction is between **exposure** and **exploitability**. This host is the most externally exposed web system because an Internet attacker does not need an initial MedDefense foothold to interact with it. However, none of Findings 005, 012, 013, or 021 independently demonstrates unauthenticated remote code execution.

Their combination nevertheless reduces several layers of web defense. Legacy TLS weakens transport protection, missing HSTS and other headers remove browser-side safeguards, TRACE introduces another unnecessary HTTP capability, and certificate expiration can disrupt patient access.

Because the application handles patient information, a successful attack affecting session confidentiality or portal availability has greater business impact than the same configuration on an ordinary informational website.

### Attack Scenario

An opportunistic attacker could first enumerate the Internet-facing portal and identify TLS 1.0, missing headers, and enabled HTTP methods. If an independent web-application weakness such as XSS were later discovered, missing Content Security Policy and enabled TRACE could increase the usefulness of that vulnerability. The attacker could then target patient sessions, credentials, or PHI.

The current findings **do not prove that XSS exists**, so it would be incorrect to claim that these findings alone form a complete compromise chain.

The 1x01 Threat Actor Matrix identifies the **public website/patient portal as the most plausible direct target for a hacktivist**, while opportunistic attackers are expected to use automated exploitation against externally accessible services.

### Priority

**Priority 3 of the three main web hosts.**

Despite being Internet-facing, the confirmed findings are primarily hardening, transport, and operational weaknesses rather than a demonstrated direct server compromise. They should be corrected promptly, but the EHR and backup NAS have greater consequences if compromised.

---

# Host 2 — Synology Backup NAS

**Host:** `NAS-01 — 10.10.2.41`

**Exposure:** **Internal-only, but reachable throughout the internal network.**

The Asset Registry identifies AST-010 as a Synology DS1621+ running DSM 7 and serving as MedDefense's primary backup repository. It is on the same network and in the same server-room environment as production infrastructure.

**Findings:**

**Finding 015 — Synology DSM Web Interface Accessible.**

The DSM administration interface is exposed on TCP/5000 and TCP/5001 and can be reached from the entire MedDefense internal network rather than only from authorized administrator systems. The scan also notes that backup data is stored unencrypted on the NAS.

### Combined Risk

**High.**

Finding 015 does not identify a software CVE, but its context significantly raises its importance. This is not an ordinary internal web management page. It controls MedDefense's principal backup repository.

The immediate weakness is excessive administrative-interface reachability. Any workstation, compromised server, unmanaged device, or attacker who obtains access to the flat internal network can communicate with the DSM management interface.

The consequence of successful NAS compromise could include changing NAS configuration, deleting recovery data, modifying administrator settings, or interfering with restoration capability. The unencrypted backups further increase confidentiality impact if storage access is obtained.

The 1x00 Gap Analysis identifies AST-010 and the backup environment as **Critical** and warns that production and backups occupy the same failure domain. A ransomware incident could therefore affect both production systems and their recovery copies.

### Attack Scenario

This interface is especially important in a ransomware kill chain.

A likely sequence is:

**initial compromise → internal lateral movement → discovery of NAS-01 → access to DSM management interface → attack recovery capability → ransomware deployment.**

The supplied 1x01 ransomware analysis explicitly maps a broader MedDefense sequence ending in **GAP-004**, the backup weakness:

**GAP-008 → GAP-007 → GAP-006 → GAP-004.**

In other words, after compromising an initial system, identity infrastructure, and potentially EHR resources, a ransomware operator has a strong incentive to attack MedDefense's backup environment before widespread encryption.

Finding 015 makes that final recovery-infrastructure step easier because the DSM administrative service is reachable throughout the internal network.

### Priority

**Priority 2 of the three main web hosts.**

NAS-01 is not directly Internet-facing, so an attacker generally needs an internal foothold first. However, ransomware groups routinely seek backup infrastructure after obtaining such a foothold. Because NAS-01 holds MedDefense's primary recovery data and lacks strong network isolation, compromise could turn a recoverable security incident into a prolonged enterprise outage.

---

# Host 3 — EHR Application Server

**Host:** `ehr-srv-01 — 10.10.2.10`

**Exposure:** **Internal, but broadly accessible because of the flat network.**

The Asset Registry identifies AST-001 as the server hosting EHR application services and AST-016 as the clinically critical EHR application used by Central and Westside. A previous EHR outage lasted nine hours and forced physicians to use paper records, demonstrating that availability has direct clinical consequences.

**Findings:**

**Finding 017 — Apache Tomcat Default Error Page Information Disclosure.**
Tomcat on TCP/8080 displays its version, `Apache Tomcat/9.0.31`, and stack traces containing internal path information. The scanner classifies the issue as Medium because the information is not directly exploitable but can assist attackers in selecting targeted exploits.

**Finding 031 — Ghostcat / AJP Investigation.**
SecurePoint followed Finding 017 by manually checking TCP/8009 and confirmed that an AJP connector was active. The scan then reported CVE-2020-1938, Ghostcat, with a CVSS score of 9.8 and stated that the condition could expose configuration files containing database credentials. It also notes that the environment's flat network permits compromised internal hosts to reach the service.

**Finding 030 — TLS Certificate Common Name Mismatch.**
Some users access `ehr-srv-01` through its IP address even though the certificate is issued to `ehr.meddefense.local`, producing browser validation warnings. The scan explicitly calls this **an operational issue rather than a security vulnerability**, so it should not be given the same weight as Findings 017 or 031.

### Combined Risk

**Critical within the scan report's assessment.**

Finding 017 by itself appears comparatively minor: it exposes software version and internal implementation details. Its importance increases because it provides exactly the information needed to conduct targeted vulnerability research.

SecurePoint used that information to investigate the Tomcat AJP service and produced Finding 031. Under the scan report's interpretation, exploitation could expose EHR server files and potentially database credentials. Because the EHR database contains PHI and is itself broadly reachable through Finding 003, disclosure of working database credentials could create a path from EHR application-server compromise to direct patient-database access.

This creates a potential relationship between:

**Finding 017 → Finding 031 → Finding 003**

Version disclosure assists vulnerability identification; exploitation of the AJP service could expose configuration/database credentials; and Finding 003 permits the PostgreSQL database to be reached from systems throughout `10.10.0.0/16`. Finding 003 explicitly confirms this broad database exposure.

### Attack Scenario

An attacker first compromises any system on MedDefense's flat network through phishing, a vulnerable server, stolen credentials, or another initial-access vector.

The attacker then enumerates internal web services and discovers Tomcat on `ehr-srv-01:8080`.

Finding 017 reveals the Tomcat version and internal path information. That information directs the attacker toward AJP on TCP/8009. In the scan report's attack model, Finding 031 then enables file disclosure from the EHR server, potentially revealing database credentials.

Those credentials become much more valuable because Finding 003 allows direct PostgreSQL connections throughout the internal `10.10.0.0/16` network.

The attacker could then access, steal, alter, or encrypt PHI.

This aligns closely with the 1x01 ransomware analysis. The Threat Actor Matrix identifies the **EHR as the primary ransomware target** because it combines Restricted PHI with severe clinical availability pressure and specifically identifies excessive EHR database reachability as part of MedDefense's ransomware exposure.

### Priority

**Priority 1 of the three main web hosts.**

The EHR server should be investigated and remediated first because it supports a Critical clinical service, contains information useful for targeted exploitation, operates within a flat network, and is closely connected to a database containing Restricted PHI.

There is an important validation caveat from Task 11: the scan reports Tomcat 9.0.31 while associating it with Ghostcat. That CVE attribution should therefore be independently validated before emergency patching. Nevertheless, **Finding 017 remains a real information-disclosure weakness**, and the investigative process it triggered remains valuable even if Finding 031 is ultimately closed as not applicable.

---

# Relative Web Remediation Priority

**1 — `ehr-srv-01`**
Highest priority because it supports the Critical EHR environment, reveals technology details useful for targeted attacks, and is reachable from a flat internal network. Its application layer also connects logically to the broadly exposed EHR database.

**2 — `NAS-01`**
Second because it is MedDefense's primary backup repository. It is internal-only, but once attackers obtain an internal foothold, the broadly reachable DSM interface gives them unnecessary proximity to recovery infrastructure.

**3 — `web-srv-01` patient portal**
Third despite being directly Internet-facing. Its exposure is the highest, but the reported findings are primarily TLS, browser-hardening, HTTP-method, and certificate-management weaknesses rather than a demonstrated direct-code-execution path. Because it handles patient information, the fixes should still be performed promptly.

This prioritization demonstrates that **Internet-facing does not automatically mean highest risk**. Risk is the combination of exposure, exploitability, asset criticality, available attack chains, and business impact.

# What Finding 017 Teaches About Medium Information-Disclosure Findings

Finding 017 demonstrates why analysts should not automatically dismiss a finding simply because the scanner labels it **Medium**.

The immediate effect of Finding 017 is only information disclosure: Tomcat reveals its exact version and internal stack/path information. That does not by itself give the attacker control of the EHR server. However, the information reduces uncertainty for the attacker. Instead of blindly testing many possible vulnerabilities, the attacker learns the application server technology and exact version and can focus research on vulnerabilities associated with that platform.

SecurePoint followed exactly that process. Finding 017 caused the analyst to inspect the AJP connector manually, which led to Finding 031 in the scan report.

The broader lesson is that **severity ratings describe the direct impact of an individual finding, not necessarily its value within an attack chain**. A Medium information-disclosure finding may function as an enabling or reconnaissance step that exposes the existence of a much more serious weakness. Version banners, stack traces, internal paths, enabled modules, and error messages can tell an attacker what to investigate next.

This also shows why manual validation matters in both directions. Finding 017 correctly justified deeper investigation, but discovering a candidate Critical CVE does not remove the need to verify that the CVE actually applies to the installed version and configuration. The proper workflow is therefore:

**information disclosure → targeted research → manual validation → confirmed vulnerability or false-positive closure.**

That is more valuable than either extreme of ignoring all Medium findings or automatically treating every vulnerability suggested by a disclosed version as confirmed.
