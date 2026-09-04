# Physical Security Walk-Through: MedDefense Central
## Structured Risk Decomposition

---

### Observation 1: Server Room Access
**Vulnerability:** The server room is protected only by a generic employee badge that is issued to clinical, administrative, and custodial personnel, with no camera coverage or visitor logging to detect or attribute unauthorized access.

**Threat:** An employee, contractor, or other person who obtains a valid staff badge could enter the server room without a legitimate business need and tamper with, disconnect, steal, or damage critical infrastructure without being recorded.

**Impact:** **Confidentiality, Integrity, and Availability** could all be affected: unauthorized physical access could expose sensitive data stored on servers, permit unauthorized modification of systems or configurations, and allow equipment to be disconnected or damaged, making clinical and business services unavailable.

**Severity:** **Critical** — The weakness provides broad, poorly monitored physical access to infrastructure supporting systems such as the EHR, billing, authentication, and file services, meaning a single unauthorized entry could affect multiple critical services and all three CIA pillars. 

### Observation 2: Network Closet
**Vulnerability:** The network closet is physically unsecured, and administrative switch credentials are displayed openly beside the network equipment, combining unrestricted physical access with exposed privileged authentication information.

**Threat:** Any person who enters the closet could use the displayed credentials to access the switch management interface and alter network configurations, connect unauthorized devices, disable ports, or redirect traffic.

**Impact:** **Integrity** is directly at risk because an attacker could modify switch configurations without authorization; *

*Availability** could be affected if ports, uplinks, or network services are disabled; and **Confidentiality** could be affected if traffic is redirected or intercepted.

**Severity:** **Critical** — The combination of an unlocked closet and exposed administrative credentials creates a low-effort path to privileged control of network infrastructure, and MedDefense’s flat network architecture increases the potential scope of compromise because servers, workstations, and medical devices share the same environment. 

### Observation 3: Nurse Station
**Vulnerability:** An unattended workstation remains logged into the EHR with a patient record visible after at least 15 minutes of inactivity, and local practice explicitly discourages users from logging out between shifts.

**Threat:** A visitor, patient, contractor, or unauthorized employee passing the nurse station could view the displayed patient information or use the active session to access additional records or perform actions under the logged-in user's account.

**Impact:** **Confidentiality** could be compromised through unauthorized viewing of protected patient information, while **Integrity** could also be affected if the unauthorized person modifies records, enters orders, or changes clinical information using the unattended authenticated session.

**Severity:** **High** — The workstation provides immediate authenticated access to sensitive clinical information without requiring an attacker to defeat technical controls, and unauthorized modification could also affect patient care decisions.

### Observation 4: Medical IoT
**Vulnerability:** The medical monitor exposes its IP address and firmware version, appears to be running firmware last updated in 2019, and is connected to the same IP range as user workstations, indicating weak network segmentation between medical devices and general endpoints.

**Threat:** An attacker who compromises a workstation or gains internal network access could identify the monitor, research weaknesses associated with its firmware version, and attempt to access, manipulate, or disrupt the device over the shared network.

**Impact:** **Integrity** could be affected if diagnostic information or device behavior is altered; **Availability** could be affected if the monitor is disabled or made unreachable; and **Confidentiality** could be affected if patient diagnostic data transmitted or stored by the device is accessed without authorization.

**Severity:** **Critical** — The risk is critical because a potentially outdated clinical device is reachable from the same flat network as ordinary workstations, creating a plausible path from endpoint compromise to manipulation or disruption of equipment used in patient care. MedDefense documentation independently notes that medical devices and workstations operate on the same broadcast domain. 

### Observation 5: Emergency Exit
**Vulnerability:** A fire exit separating a public waiting area from a restricted administrative wing is intentionally propped open, bypassing the physical access control that should restrict entry into areas containing IT and security personnel.

**Threat:** A member of the public could enter the restricted wing through the unsecured doorway and gain physical access to offices, unattended workstations, documents, or other internal resources without presenting credentials or being challenged at the access point.

**Impact:** **Confidentiality** could be affected through unauthorized access to sensitive documents or systems; **Integrity** could be affected through tampering with devices or records; and **Availability** could be affected if equipment is damaged, disconnected, or stolen.

**Severity:** **High** — The condition creates a direct, unauthenticated path from a public area into a restricted administrative zone containing the IT department and security leadership offices, substantially increasing the likelihood of unauthorized physical access and subsequent compromise.
