# Threat Analysis: IoT Smart Thermostat

**Prepared for:** Executive Security Review
**System:** Wi-Fi connected smart thermostat with mobile app control, temperature data collection, and OTA firmware updates

---

## 1. IoT-Specific Threats

Unlike typical web applications, IoT devices combine physical exposure, constrained hardware, and long deployment lifecycles. Six threats specific to this class of device:

1. **Physical Tampering** — The device sits in an accessible location (a wall) with no physical security beyond the homeowner's front door, unlike a server in a locked data center.
2. **Weak or Default Credentials** — Many IoT devices ship with hardcoded or default admin passwords (e.g., `admin/admin`) that are never rotated, unlike web apps that enforce password policies at signup.
3. **Unencrypted Local Communications** — Local network protocols (e.g., device-to-hub) often skip TLS for performance/cost reasons, exposing commands to anyone on the same Wi-Fi.
4. **Firmware Vulnerabilities & Lack of Patching** — Devices run for 5–10 years and often lack automatic update mechanisms or vendor support, unlike web apps patched centrally within hours.
5. **Insecure OTA Update Mechanism** — If firmware updates aren't signed, an attacker can push malicious firmware directly to the device.
6. **Resource-Constrained Hardware Limits Security Controls** — Low-power microcontrollers may lack the CPU/memory to run full encryption stacks or intrusion detection, forcing tradeoffs not seen in cloud environments.

## 2. Physical Access Attack Chain

### Detailed Threat: Physical Access Compromise

- **Description:** An attacker with brief physical access to the thermostat (e.g., a visitor, contractor, or burglar) removes it from the wall mount to access exposed hardware interfaces.
- **Attack Scenario:** The attacker unclips the thermostat, exposing a UART/JTAG debug header on the PCB. Using a $20 USB-to-serial adapter, they connect to the debug port, dump the firmware and stored Wi-Fi credentials from flash memory, and extract the device's private key used to authenticate to the cloud API. They reattach the thermostat, leaving no visible sign of tampering.
- **Impact:** High — the extracted Wi-Fi password grants network access; the device certificate/key can be used to impersonate the thermostat in the cloud, potentially pivoting to other devices on the same home network or issuing malicious commands (e.g., disabling heat in winter).
- **Likelihood:** Medium — requires physical proximity and moderate hardware skill, but tools and tutorials for UART extraction are widely available online.
- **Mitigation:** Disable or physically remove debug headers (UART/JTAG) on production units, encrypt flash storage so extracted data is unusable without a hardware security module (HSM) key, and use a Trusted Platform Module (TPM) or secure element to store credentials outside of readable flash.

### Attack Chain Summary

```
1. Physical access to device (visitor, theft, delivery tampering)
   ↓
2. Remove device from wall mount / open enclosure
   ↓
3. Locate and connect to exposed UART/JTAG debug interface
   ↓
4. Dump firmware image and NVRAM contents via serial console
   ↓
5. Extract Wi-Fi PSK and device authentication certificate/key
   ↓
6. Use Wi-Fi PSK for local network access
   OR use device credentials to impersonate thermostat to cloud API
   ↓
7. Impact: network pivot, false telemetry, malicious commands, privacy loss
```

### DREAD Score — Physical Access Compromise

**Formula:** `DREAD = (Damage + Reproducibility + Exploitability + Affected Users + Discoverability) / 5`, each scored 1–10.

| Factor | Score | Reasoning |
|---|---|---|
| Damage | 8 | Wi-Fi and cloud credentials extracted; enables network pivot |
| Reproducibility | 7 | Reliable once the debug port is located and accessible |
| Exploitability | 5 | Requires physical access and basic hardware tools/skills |
| Affected Users | 3 | Limited to the single household whose device is accessed |
| Discoverability | 6 | UART pinouts for popular thermostat models are documented online |

**DREAD Total = (8 + 7 + 5 + 3 + 6) / 5 = 5.8 → Medium-High Risk**

## 3. OTA Update Security Design

### Detailed Threat: Malicious Firmware Injection via Unsigned OTA

- **Description:** The OTA update channel accepts any firmware image without verifying its authenticity, allowing an attacker to push a malicious build.
- **Attack Scenario:** An attacker performs a DNS spoofing attack against the thermostat's update-check request, redirecting it to an attacker-controlled server that serves a trojanized firmware image. The device installs it, giving the attacker a persistent foothold that can exfiltrate Wi-Fi credentials or join a botnet.
- **Impact:** Critical — full device compromise, potential home network compromise, and reputational damage at scale if exploited across many devices (fleet-wide risk).
- **Likelihood:** Medium — requires network-level positioning (DNS spoofing or rogue AP), which is achievable on shared/public networks or via router compromise.
- **Mitigation:** Require cryptographically signed firmware images (verified against a vendor public key burned into the bootloader), deliver updates exclusively over TLS with certificate pinning, and reject any image that fails signature verification before flashing.

### DREAD Score — Malicious Firmware Injection

| Factor | Score | Reasoning |
|---|---|---|
| Damage | 10 | Full device takeover, potential botnet enrollment fleet-wide |
| Reproducibility | 5 | Requires network positioning, not always trivially available |
| Exploitability | 6 | DNS spoofing tools are accessible to moderately skilled attackers |
| Affected Users | 8 | Fleet-wide risk if the same vulnerability exists across all units |
| Discoverability | 5 | Requires firmware/traffic analysis to find the missing verification |

**DREAD Total = (10 + 5 + 6 + 8 + 5) / 5 = 6.8 → High Risk**

### Essential OTA Security Requirements

1. **Code Signing** — Every firmware image must be signed with a vendor private key; the bootloader verifies the signature against an immutable public key before allowing execution.
2. **Secure Boot Chain** — Each boot stage verifies the integrity/signature of the next stage, preventing execution of unsigned or modified code even if flash is directly reprogrammed.
3. **Encrypted Update Channel** — All OTA traffic uses TLS 1.2+ with certificate pinning to the vendor's update server, preventing MITM substitution of the firmware image.
4. **Rollback Protection (Anti-Downgrade)** — Firmware includes a monotonically increasing version counter; the bootloader refuses to install an older, potentially vulnerable version even if it is validly signed.
5. **Atomic, Fail-Safe Updates (A/B Partitioning)** — Updates write to an inactive partition and only switch on success, so a failed or interrupted update cannot brick the device or leave it in an insecure state.
6. **Update Integrity Verification** — A cryptographic hash (SHA-256) of the downloaded image is verified before installation, independent of the signature check, to catch corruption or partial downloads.

### Detailed Threat: Weak Default Credentials on Local Setup Interface

- **Description:** The thermostat exposes a local web setup interface (used during initial Wi-Fi provisioning) protected only by a hardcoded default password shared across all units of the same model.
- **Attack Scenario:** An attacker within Wi-Fi range during the brief provisioning window connects to the thermostat's temporary setup access point and logs in using the default credentials found in the publicly available user manual, then reconfigures the device to join an attacker-controlled network instead of the homeowner's.
- **Impact:** Medium-High — allows full device reconfiguration and can be used as a foothold to intercept the legitimate Wi-Fi credentials the homeowner enters during setup.
- **Likelihood:** Low-Medium — requires the attacker to be physically nearby during the narrow provisioning window, but automated scanning tools can detect open setup access points.
- **Mitigation:** Generate a unique, random default password per device (printed on the device label, not documented publicly), require the password to be changed on first login, and automatically close the setup access point after a short timeout.

### DREAD Score — Weak Default Credentials

| Factor | Score | Reasoning |
|---|---|---|
| Damage | 6 | Device reconfiguration and Wi-Fi credential interception |
| Reproducibility | 6 | Reliable if attacker is present during setup window |
| Exploitability | 7 | Default credentials are publicly documented, no skill needed |
| Affected Users | 2 | Limited to the single household during its setup window |
| Discoverability | 8 | Default credentials for consumer IoT devices are widely published |

**DREAD Total = (6 + 6 + 7 + 2 + 8) / 5 = 5.8 → Medium-High Risk**

## Glossary

- **OTA:** Over-The-Air firmware update delivery. **UART/JTAG:** Hardware debug interfaces for low-level chip access.
- **DREAD:** Damage, Reproducibility, Exploitability, Affected Users, Discoverability.
- **Secure Boot:** Cryptographic verification of each firmware stage before execution. **A/B Partitioning:** Dual-partition scheme enabling safe rollback.

## Real-World Constraints Considered

- **Budget:** Adding a secure element/TPM increases per-unit bill-of-materials cost; this is justified only for the credential-storage risk (DREAD 5.8) given the scale of deployment, not applied indiscriminately.
- **Hardware constraints:** Low-power microcontrollers may not support full TLS stacks; lightweight cipher suites (e.g., ECC-based) should be evaluated to balance security and power draw.
- **Device lifespan:** A 5–10 year expected lifespan requires the vendor to commit to a firmware support and patching policy at launch, not as an afterthought.
- **Field deployment:** Recalling devices for hardware fixes is costly; software mitigations (disabling debug interfaces) serve as an interim control pending the next hardware revision.

## Risk Register Summary

The table below consolidates the three DREAD-scored threats analyzed above for quick executive reference.

| Threat | Category | DREAD Score | Risk Level |
|---|---|---|---|
| Physical Access Compromise | Hardware Tampering | 5.8 | Medium-High |
| Malicious Firmware Injection | OTA / Supply Chain | 6.8 | High |
| Weak Default Credentials | Local Interface | 5.8 | Medium-High |

## Summary

The highest-priority risk is the unsigned OTA update path (DREAD 6.8), which could compromise the entire device fleet rather than a single household, making it the top remediation priority. Physical access compromise and weak default credentials (DREAD 5.8 each) are lower in scale but still significant given how easily debug interfaces and default passwords can be exploited once discovered.

Stakeholders should treat code signing and secure boot as launch-blocking requirements rather than post-launch enhancements, since retrofitting cryptographic trust into an already-deployed fleet is substantially more expensive than building it in from the start. Physical hardening (removing debug headers, encrypting flash) should be scheduled for the next hardware revision, with firmware-level mitigations deployed in the interim to reduce exposure without a costly product recall.
