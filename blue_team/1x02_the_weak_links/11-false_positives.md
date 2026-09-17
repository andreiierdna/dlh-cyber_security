# Task 11 — The False Positives

False-positive validation is an essential part of vulnerability management because automated scanners often identify vulnerabilities from product names and version numbers without confirming every exploitation prerequisite. In the MedDefense scan, three findings require this type of validation. Findings 010 and 031 contain authoritative version mismatches that make the reported CVEs inapplicable to the detected software versions, while Finding 020 was explicitly identified by SecurePoint as a potential false positive because the scanner did not establish the prerequisite configuration necessary for exploitation.

## 1. Finding 020 — OpenSSH CVE-2023-38408

**Finding ID:** Finding 020 — Medium

**Reported Vulnerability:** OpenSSH Version Outdated / **CVE-2023-38408** on `backup-srv-01 (10.10.2.40)`.

The scanner detected `OpenSSH_8.9p1 Ubuntu-3ubuntu0.1` and associated it with CVE-2023-38408, assigning the CVE a 9.8 CVSS score. However, SecurePoint explicitly warned that the finding **may be a false positive** because exploitation requires ssh-agent forwarding to an attacker-controlled system and stated that this condition is unlikely in the backup server's operational context.

**Why It Is a False Positive:** The scanner correctly identified an OpenSSH version within the broad affected version range, but version detection alone does not demonstrate that `backup-srv-01` is exploitable. CVE-2023-38408 affects the **PKCS#11 functionality of `ssh-agent`**. NVD states that exploitation requires an SSH agent to be **forwarded to an attacker-controlled system**. Merely running an affected OpenSSH package or exposing `sshd` on TCP/22 does not satisfy this condition.

This distinction is important because the vulnerability is associated with the client-side `ssh-agent` behavior rather than simply the presence of an OpenSSH server daemon. If MedDefense administrators do not run or forward an SSH agent from this backup server to untrusted systems, the exploitation path identified by CVE-2023-38408 does not exist.

The available scan evidence therefore supports SecurePoint's conclusion that this is a **suspected contextual false positive**, although final closure should occur only after the agent-forwarding configuration is verified.

**Validation Method:** An administrator should inspect `backup-srv-01` for the actual prerequisite conditions rather than relying on its OpenSSH version alone. Validation should include checking whether `ssh-agent` processes are normally running for administrative or service accounts, whether `SSH_AUTH_SOCK` is present in relevant sessions, whether administrators use `ssh -A` or `ForwardAgent yes`, and whether the server makes outbound SSH connections to systems that are not fully trusted. Relevant SSH client configuration files and administrative procedures should also be reviewed.

If no agent is being forwarded from the vulnerable OpenSSH environment to attacker-controlled or untrusted systems, CVE-2023-38408 is not exploitable in MedDefense's documented configuration and the finding can be closed as a false positive.

**Risk of Acting on This FP:** Treating the version match alone as proof of a Critical RCE could cause unnecessary emergency change activity on `backup-srv-01`, including administrator time, change-control work, compatibility testing, maintenance windows, and possible interruption of administrative access to a server supporting MedDefense backups. Those resources would be diverted from confirmed vulnerabilities with demonstrated attack paths.

Updating OpenSSH may still be sensible as routine security maintenance, but it should not be justified as an emergency CVE-2023-38408 remediation unless the prerequisite configuration actually exists.

**Risk of Not Validating:** Dismissing the finding without checking would create the opposite problem. If administrators do use agent forwarding and an agent can be exposed to an attacker-controlled SSH server, the vulnerability can result in remote code execution. NVD rates the vulnerability **9.8 Critical**. A vulnerability on backup infrastructure deserves careful verification because compromise of recovery systems could significantly worsen a ransomware incident.

---

## 2. Finding 010 — BD Alaris CVE-2020-25165

**Finding ID:** Finding 010 — High

**Reported Vulnerability:** **CVE-2020-25165** affecting BD Alaris infusion pumps at `10.10.3.40–46`.

The scanner reports that the pumps run **firmware version 12.1.2** and states that they are vulnerable to CVE-2020-25165, a network-session vulnerability capable of causing denial of service.

**Why It Is a False Positive:** The scanner's CVE-to-version mapping conflicts with both NVD and the manufacturer's own security advisory.

NVD states that CVE-2020-25165 affects the **BD Alaris PC Unit Model 8015 version 9.33.1 and earlier**, together with Alaris Systems Manager version 4.33 and earlier.

More importantly, BD's official security bulletin states that the vulnerability was remediated in:

**Alaris PC Unit software version 12.1.1 and newer.**

BD explicitly recommends upgrading to version 12.1.1 or later.

MedDefense's scanner detected **version 12.1.2**, which is newer than the vendor's fixed version. Therefore, assuming the detected firmware version and device model are accurate, **CVE-2020-25165 does not apply to these pumps**.

This is a classic version-mapping false positive: the scanner recognized the product family but associated a vulnerability with a firmware release outside the affected range.

There is an important qualification: the scan separately found that seven tested pumps respond to the default `admin/admin` management credentials. **That default-credential condition is not a false positive and still requires remediation.** Only the CVE-2020-25165 attribution should be closed.

**Validation Method:** Biomedical Engineering and IT should verify the exact device model and firmware version directly from the Alaris PC Unit management interface or device inventory. The result should be compared to the BD advisory.

If the devices are confirmed as Alaris 8015 units running **12.1.2**, they are beyond the 12.1.1 remediation level and the CVE finding should be closed as a false positive. MedDefense should separately verify the version of any Alaris Systems Manager installation, because Systems Manager version 4.33 and earlier is also included in the affected-product range.

**Risk of Acting on This FP:** Medical-device changes can require substantially more effort than ordinary server patching. An unnecessary emergency firmware remediation could consume Biomedical Engineering and IT resources, require vendor coordination, trigger clinical testing and change-control requirements, and potentially require infusion devices to be removed temporarily from patient-care availability.

Treating the false CVE match as the problem could also distract remediation efforts from the **actual confirmed issue—unchanged default credentials and inadequate medical-device segmentation**.

**Risk of Not Validating:** The finding cannot simply be dismissed based on an assumed firmware number. If the scanner incorrectly identified the installed version, if older pumps exist elsewhere in the fleet, or if MedDefense operates an affected Alaris Systems Manager version, CVE-2020-25165 could still be present. Successful exploitation can disrupt wireless functionality and force the affected PC Unit into manual operation. In a clinical environment, that availability impact makes accurate version verification essential.

---

## 3. Finding 031 — Apache Tomcat Ghostcat

**Finding ID:** Finding 031 — High

**Reported Vulnerability:** **CVE-2020-1938 (Ghostcat)** on `ehr-srv-01 (10.10.2.10)` through the AJP connector on TCP/8009.

SecurePoint manually confirmed that an AJP connector is active and then associated it with CVE-2020-1938, stating that an attacker could potentially read files containing EHR database credentials.

**Why It Is a False Positive:** Finding 017 identifies the installed application server as:

**Apache Tomcat 9.0.31.**

That version is significant because authoritative vulnerability information identifies **9.0.31 as the fixed release**, not an affected release.

NVD defines the vulnerable Tomcat 9 range as **9.0.0.M1 through 9.0.30**, or equivalently versions below 9.0.31. NVD specifically states that users can mitigate CVE-2020-1938 by upgrading to Tomcat **9.0.31 or later**.

Apache's own security documentation likewise lists CVE-2020-1938 under vulnerabilities **fixed in Apache Tomcat 9.0.31**.

The manual verification proved that **AJP is listening on port 8009**. It did **not** prove that Tomcat 9.0.31 remains vulnerable to Ghostcat. An open AJP connector and an exploitable Ghostcat implementation are not the same thing.

Therefore, assuming the detected Tomcat version is accurate, the attribution of **CVE-2020-1938 to Tomcat 9.0.31 is a false positive**.

**Validation Method:** The administrator should verify the actual installed Tomcat build directly rather than relying only on the HTTP error-page banner. This can be done using Tomcat's version information or package/application files on `ehr-srv-01`.

The AJP configuration should then be reviewed to determine its bind address, authentication/secret settings, and whether AJP is operationally required. If the server is genuinely running **Tomcat 9.0.31 or newer**, CVE-2020-1938 should be closed as not applicable.

The exposed AJP service should still undergo security-hardening review. Closing Ghostcat as a false positive does not automatically mean that exposing TCP/8009 across MedDefense's flat network is good architecture.

**Risk of Acting on This FP:** Treating Ghostcat as a confirmed 9.8 vulnerability could trigger an unnecessary emergency EHR application upgrade or redeployment. Because `ehr-srv-01` supports clinical documentation, unnecessary changes could require vendor coordination, application regression testing, a maintenance window, clinician communication, and potentially unnecessary EHR downtime.

Emergency remediation resources would also be diverted from confirmed EHR weaknesses such as the unrestricted database exposure documented elsewhere in the scan.

**Risk of Not Validating:** A false-positive conclusion should never be based solely on assumptions. If the reported `9.0.31` banner is inaccurate, if an older Tomcat installation is actually executing, or if the environment contains another vulnerable Tomcat instance, Ghostcat may still be exploitable. On affected versions, NVD states that an attacker who can reach AJP can retrieve files within the web application and, under additional circumstances, potentially execute code. Because this server supports the EHR, dismissing a genuine Ghostcat vulnerability without checking the installed binaries would create significant PHI and clinical risk.

---

# Expected False Positive Rate and Why Validation Matters

The vulnerability report itself states that OpenVAS in this configuration has an expected **false-positive rate of approximately 5–10%** and explicitly recommends manual verification of high-value findings before remediation resources are committed.

For a report containing **31 findings**, a 5–10% false-positive rate corresponds to approximately **1.6 to 3.1 findings**, or roughly **2–3 false positives**. Finding three applicability problems in this assessment is therefore consistent with the scanner's own expected error rate.

Manual validation is essential because automated scanners generally make decisions from observable evidence such as version strings, open ports, service banners, configuration responses, and vulnerability databases. They may not understand the complete operational context or every exploitation prerequisite. Finding 020 demonstrates a **missing prerequisite problem**: the OpenSSH version is potentially vulnerable, but exploitation depends on ssh-agent forwarding to an attacker-controlled system. Finding 010 demonstrates a **version-mapping problem**: the scanner associated a CVE with firmware 12.1.2 even though BD states that 12.1.1 and later contain the remediation. Finding 031 demonstrates the same principle on the EHR server: confirming that AJP is open does not prove Ghostcat when Tomcat 9.0.31 is the vendor's fixed release. Vulnerability management therefore requires validation before action. Without it, MedDefense could waste staff time, vendor support, maintenance windows, clinical change capacity, and remediation budget on vulnerabilities that are not actually present. Conversely, dismissing findings without validation can leave a genuine Critical vulnerability exposed. The correct process is to **verify the affected version and exploitation prerequisites, document the evidence, then close the finding as false positive or escalate it for remediation**.
