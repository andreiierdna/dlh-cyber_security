# Task 14 — The Network Posture

MedDefense's flat network amplifies vulnerability risk because compromise of one host is not naturally contained within a security zone. 

The **Risk Amplification Factor** used below is a contextual estimate of how much the flat architecture increases the practical risk of each CVE by expanding both pre-exploitation reachability and post-exploitation blast radius. It is **not a CVSS multiplier**.

---

## 1. CVE-2021-44790 — Apache mod_lua Buffer Overflow

CVE: CVE-2021-44790

Host: billing-srv-01 — 10.10.2.15

CVSS Base Score: 9.8

### Scenario A: Current (flat network)

Who can reach this vulnerability: Systems throughout the MedDefense `10.10.0.0/16` environment can potentially communicate with `billing-srv-01`. This includes workstations in `10.10.1.0/24`, servers in `10.10.2.0/24`, medical devices in `10.10.3.0/24`, and other routed MedDefense systems. There is no meaningful internal segmentation preventing a compromised workstation or other internal host from attempting to reach the vulnerable Apache service.

What the attacker can reach AFTER exploitation: Successful exploitation can provide code execution on `billing-srv-01`. Finding 002 provides an additional privilege-escalation path from an Apache worker context to root. From the compromised billing server, the attacker has network proximity to the EHR database, Active Directory, backup infrastructure, workstations, and medical-device networks. The attacker would still need credentials or additional vulnerabilities to compromise those systems, but the flat network does not provide a firewall boundary to contain the attacker.

Effective Risk: Critical. A 9.8 remote-code-execution vulnerability on a previously compromised billing server can become an enterprise lateral-movement foothold rather than remaining a billing-only incident.

### Scenario B: Hypothetical (segmented network)

Who can reach this vulnerability: Only authorized systems in the billing VLAN, such as billing workstations and required application services, would be permitted to communicate with the vulnerable Apache service.

What the attacker can reach AFTER exploitation: After compromising `billing-srv-01`, the attacker would initially remain inside the billing VLAN. Access to the EHR, Domain Controllers, backup systems, and medical devices would require crossing a firewall through an explicitly permitted rule or discovering another pivot path.

Effective Risk: High. The Apache vulnerability would still require urgent remediation, but the compromise would be much more likely to remain confined to billing infrastructure.

Risk Amplification Factor: 8.3x

The flat network increases the practical risk by approximately **8.3x** because it changes the likely blast radius from one business segment to multiple Critical environments, including EHR, Active Directory, backups, and clinical systems.

---

## 2. CVE-2019-0708 — BlueKeep

CVE: CVE-2019-0708

Host: WS-RAD-01 — 10.10.1.70

CVSS Base Score: 9.8

### Scenario A: Current (flat network)

Who can reach this vulnerability: Systems throughout the internal `10.10.0.0/16` environment can potentially reach the MRI workstation. The scan specifically confirms that `WS-RAD-01` is located on `10.10.1.0/24` with ordinary workstations and has no VLAN isolation. Any compromised internal endpoint capable of reaching TCP/3389 can therefore attempt to exploit BlueKeep.

What the attacker can reach AFTER exploitation: Compromise of the MRI workstation does not remain isolated to Radiology. The attacker can use the workstation as a foothold to scan or attack PACS, EHR systems, Active Directory, backup infrastructure, user workstations, and other medical devices. Because the workstation is part of the MRI workflow, compromise could also directly affect diagnostic imaging availability.

Effective Risk: Critical. BlueKeep is already a remotely exploitable vulnerability on an unsupported clinical system, and the flat network gives the compromised device enterprise-wide lateral-movement value.

### Scenario B: Hypothetical (segmented network)

Who can reach this vulnerability: Only systems within a dedicated Radiology or medical-device VLAN, together with specifically authorized administrative systems, would be able to reach the MRI workstation. Unrelated workstations and servers would be blocked from accessing RDP and SMB.

What the attacker can reach AFTER exploitation: Successful exploitation would primarily affect the MRI security zone. Required communication with PACS could remain permitted, but communication toward billing, general workstations, backup infrastructure, and unrelated medical devices would be denied by default.

Effective Risk: High. BlueKeep would still threaten MRI availability, but compromise would be much less likely to become an organization-wide lateral-movement event.

Risk Amplification Factor: 10.0x

The flat network increases the practical risk by approximately **10.0x** because an unsupported medical device that should be tightly isolated instead has network proximity to unrelated enterprise and clinical systems. Segmentation is especially important here because the Windows XP operating system cannot easily be replaced without affecting medical-device certification.

---

## 3. CVE-2021-34527 — PrintNightmare

CVE: CVE-2021-34527

Host: print-srv-01 — 10.10.2.31

CVSS Base Score: 8.8

### Scenario A: Current (flat network)

Who can reach this vulnerability: Workstations and systems throughout MedDefense's internal network can potentially communicate with the print server. Because printing is a shared enterprise service and the environment lacks effective segmentation, the server has broad network exposure to user endpoints.

What the attacker can reach AFTER exploitation: After compromising `print-srv-01`, an attacker obtains a Windows server foothold in the Central server environment. From that position, the attacker can attempt to enumerate and attack Active Directory, EHR systems, file servers, billing infrastructure, backup systems, and user endpoints. Credentials recovered from the print server could further assist lateral movement.

Effective Risk: Critical. Although the CVSS score is 8.8, the print server's central position and broad internal connectivity make exploitation valuable for lateral movement toward higher-value systems.

### Scenario B: Hypothetical (segmented network)

Who can reach this vulnerability: Only authorized workstation VLANs and print-management systems would be allowed to communicate with the print server. Critical application servers and medical-device VLANs would have no reason to initiate unrestricted connections to it.

What the attacker can reach AFTER exploitation: Compromise would initially remain limited to the printing security zone and the specific communications permitted through its firewall rules. Direct access from the print server to EHR databases, medical devices, and backup management systems could be blocked.

Effective Risk: High. PrintNightmare would remain a serious vulnerability, but a compromised print server would be significantly less useful as an enterprise pivot point.

Risk Amplification Factor: 6.5x

The flat network increases the practical risk by approximately **6.5x** because it turns compromise of a supporting infrastructure server into a possible lateral-movement path toward Critical authentication, clinical, and recovery systems.

---

## Network Posture Summary

The flat MedDefense network creates an aggregate risk multiplier across the entire vulnerability scan because almost every successful compromise can become a starting point for lateral movement. Vulnerabilities that should be confined to billing, Radiology, printing, or another individual security zone instead provide attackers with network proximity to the broader `10.10.0.0/16` environment. Across the three examples above, the estimated Risk Amplification Factors range from **6.5x to 10.0x**, depending on the affected system's role, reachability, and value as a pivot point. Segmentation is arguably more impactful than patching any single CVE because a patch removes one known attack path, while segmentation limits the blast radius of **all current and future vulnerabilities**. Patching CVE-2021-44790 protects one Apache service; properly separating billing, EHR, Active Directory, backups, workstations, and medical devices reduces the ability of an attacker to turn any successful exploit into an enterprise-wide incident. Patching and segmentation are both necessary, but segmentation provides a persistent containment control even when an unknown or unpatched vulnerability is successfully exploited.
