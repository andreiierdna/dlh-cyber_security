# Task 15 — The Medical IoT

MedDefense's medical-device exposure is more serious than a conventional endpoint problem because the affected assets directly support patient monitoring, diagnostic imaging, and medication delivery. The Asset Registry identifies the Philips IntelliVue fleet as AST-036 and the BD Alaris infusion-pump fleet as AST-037; both use `10.10.3.0/24` addressing but have **no enforced VLAN separation** from the wider MedDefense network. The 1x00 Gap Analysis consequently classifies Medical IoT and Clinical Devices as a **Critical** asset category because manipulation or disruption can affect bedside treatment.

## 1. BD Alaris Assessment

**Scan Finding:** Finding 010 — BD Alaris Infusion Pump Known Vulnerabilities
**Affected MedDefense Asset:** AST-037 — BD Alaris infusion-pump fleet
**Detected Software:** 12.1.2
**Scan CVE:** CVE-2020-25165

The scan reports BD Alaris pumps at `10.10.3.40-46`, identifies software version 12.1.2, associates the devices with CVE-2020-25165, and states that all seven tested pumps responded to the default `admin/admin` credentials.

### CVE-2020-25165 Validation

BD's original advisory describes CVE-2020-25165 as a **network-session vulnerability in the authentication process between the Alaris PC Unit and Alaris Systems Manager**. An attacker with access to the relevant wireless network could redirect authentication traffic and potentially cause a denial of service affecting wireless connectivity. BD states that the pump would continue operating as programmed, but functions such as EMR pre-population and wireless Guardrails updates could become unavailable.

However, BD also states that **Alaris PC Unit 8015 software version 12.1.1 and newer addresses CVE-2020-25165**. The affected PC Unit range is version 9.33.1 and earlier. MedDefense's reported version is **12.1.2**, so the scan's specific attribution of CVE-2020-25165 to those pumps is not valid if the detected version is accurate.

This does **not** mean the 12.1.2 pumps are secure.

### Real BD Vulnerabilities Affecting the 12.1.2 Generation

BD published a later security bulletin covering **BD Alaris System with Guardrails Suite MX version 12.1.3 and earlier**. That scope includes MedDefense's 12.1.2 generation. For the Alaris PC Unit Model 8015, BD identifies:

**CVE-2023-30559 — Wireless Card Firmware Improperly Signed.** An attacker with physical access may modify the wireless-card firmware, with potential availability impact.

**CVE-2023-30560 — PCU Configuration Lacks Authentication.** With physical access, an attacker may modify PCU configuration without authentication. BD states that modifications could affect firmware, datasets, network credentials, and log files and may affect device functionality.

**CVE-2023-30561 — Lack of Cryptographic Security of the IUI Bus.** A specially connected device could potentially read or modify communications between the PCU and its modules.

BD also identifies **CVE-2023-30562** in Guardrails Editor 12.1.2 and earlier. A modified Guardrails dataset can potentially be distributed to PCUs, and BD states that such tampering could result in activation of an undesired dataset, although existing safety controls reduce the assessed probability of harm.

### Vendor-Recommended Mitigation

BD recommends updating the Alaris System to supported releases where regulatory authorization permits, but it also emphasizes compensating network controls. The vendor specifically recommends using firewalls and ACLs so pumps communicate only over required ports to required endpoints, placing Alaris PCUs on their **own VLAN**, restricting Systems Manager access, enabling an authentication challenge password for network-configuration changes, rotating wireless credentials, monitoring for unexpected network activity, and restricting the segment to approved devices.

This is especially important because BD states that some PCU vulnerabilities remain present even in PCU version 12.3.1, meaning network controls remain necessary rather than treating firmware updates as the only protection.

### Has MedDefense Implemented the Recommendation?

**No, not adequately.**

MedDefense has not implemented the vendor's most important compensating control: network segmentation. AST-037 is documented on `10.10.3.0/24`, but there is **no enforced VLAN separation**, and the medical-device environment remains reachable from the wider internal network.

The scan also found that all seven tested pumps accepted the default `admin/admin` credentials. That is inconsistent with the principle of limiting administrative access and strengthening authentication around the device fleet.

Therefore, although **CVE-2020-25165 itself does not appear applicable to firmware 12.1.2**, MedDefense still has a genuine Alaris security problem: its device generation is covered by later BD advisories, the pumps are insufficiently isolated, and default credentials remain in use.

**Assessment: Critical contextual risk because of patient-care function and inadequate compensating controls.**

---

## 2. Philips IntelliVue Assessment

**Scan Finding:** Finding 016 — Medical Device HTTP Interface Accessible
**Affected MedDefense Asset:** AST-036 — Philips IntelliVue patient-monitor fleet
**Hosts:** Multiple systems in `10.10.3.10-32`

The scan found 13 IntelliVue monitors exposing TCP/80, TCP/443, and TCP/2575. It states that their web-management and HL7 interfaces are reachable throughout the internal network and that they have no authentication protection beyond the network layer—a control that provides little protection in MedDefense's flat architecture.

### What Data Flows Through the Interfaces?

Philips documentation shows that the IntelliVue ecosystem handles substantially more than generic device-status information. IntelliBridge can collect **physiological parameters, waveforms, device settings, and alarm information** from bedside equipment and forward those data to central monitoring, nurse paging, documentation systems, and electronic patient records.

Philips documentation also describes HL7 export of numeric clinical measurements and shows that IntelliVue systems can exchange patient/bed context and vital-sign information with hospital systems.

Depending on the device and configuration, information associated with these interfaces can therefore include patient vital signs, measurement values, alarm conditions, device operating information, bed context, and data intended for the EHR or other clinical systems.

### What Could an Attacker with Network Access See or Do?

The **confirmed capability** is network reachability. A compromised internal endpoint can identify and connect to the exposed HTTP/HTTPS and HL7 services because no segmentation prevents it. The web interface may expose device status, configuration, firmware information, or management functions depending on the configured access level.

An attacker able to obtain clinical data from the HL7 interface could potentially expose sensitive bedside information such as current physiological measurements, alarms, and patient-associated clinical data. Philips confirms that its monitoring ecosystem transfers parameters, waveforms, device settings, and alarm information between bedside devices and clinical information systems.

The scan does **not**, however, prove that a remote attacker can change measurements, disable alarms, or directly control a monitor through TCP/2575. Those actions would require manual protocol and authorization testing. The defensible conclusion is therefore that MedDefense has confirmed **unauthorized network proximity to clinically sensitive interfaces**, with confidentiality and availability risk and a potential integrity risk that requires further validation.

Because these are patient-monitoring systems, even denial of service has a patient-safety dimension: loss of networked monitoring or delayed alarm delivery could reduce clinicians' visibility into changes in a patient's condition.

---

## 3. Finding 024 — Unencrypted DICOM as a Related Medical-Device Weakness

**Scan Finding:** Finding 024 — DICOM Service Detected Without Encryption
**Affected Host:** `pacs-srv-01 — 10.10.2.12`
**Related Medical Device:** MRI / Radiology environment

Finding 024 confirms that DICOM communication on TCP/4242 and TCP/11112 is not protected by TLS. The scan specifically states that this traffic contains **patient identifiers and medical images** and that communications between the MRI workstation, radiology workstations, and PACS traverse the network in cleartext.

This finding is important to the Medical IoT assessment because medical devices do not operate independently. They form clinical workflows involving acquisition devices, workstations, servers, patient records, and monitoring systems.

An attacker positioned where DICOM traffic can be observed could expose patient identifiers and diagnostic imaging. If the attacker also obtains the ability to intercept or modify traffic, integrity becomes a patient-safety concern because clinicians depend on diagnostic images for treatment decisions.

Finding 024 also combines with **Finding 004**, the unsupported Windows XP MRI control workstation. The MRI system already has multiple legacy vulnerabilities and no effective VLAN isolation, meaning the insecure DICOM workflow sits inside an environment where the imaging endpoint itself is unusually vulnerable.

---

## 4. Combined Medical IoT Risk

Findings 010, 016, and 024 should not be considered separate technical tickets. Together they demonstrate an architectural problem: medical devices and clinical protocols that depend heavily on network trust are operating inside a broadly reachable internal environment.

The BD pumps support medication infusion, the Philips devices monitor patient condition, and the PACS/DICOM environment carries diagnostic imaging. The 1x00 Gap Analysis therefore identifies missing **medical-device VLANs, default-deny internal access, behavioral monitoring, configuration recovery, and device restoration procedures** as a Critical gap. It concludes that an attacker with internal access could target monitors, pumps, or nurse-call infrastructure and that unauthorized device alteration or outages could affect treatment or medication delivery.

The most important remediation is therefore not simply "patch every device." MedDefense needs to establish a dedicated medical-device security zone with explicit allow-list rules for required clinical communications, change default credentials, identify exact device/software versions, monitor medical-device network traffic, and coordinate vendor-approved software updates.

---

## 5. Patient Safety Dimension

Medical-device vulnerabilities belong to a different risk category because compromise can affect not only information confidentiality but also the **physical delivery of healthcare**. A compromised workstation may result in credential theft, malware, or disclosure of patient records; a compromised infusion environment can potentially interfere with medication-delivery workflows or the safety datasets clinicians rely upon. The worst credible workstation outcome is usually loss of data or business capability, while the worst credible infusion-pump outcome includes an unsafe medication-delivery condition that could directly harm a patient. Similarly, disruption of patient monitors can reduce clinical awareness of deteriorating vital signs, turning cybersecurity availability into a patient-safety issue.

---

## 6. Remediation Challenge

**Regulatory and safety validation:** Medical-device software is part of a regulated clinical product. Hospitals generally cannot treat a pump or monitor like a desktop PC and independently install arbitrary firmware, operating-system patches, or security tools. Updates may require manufacturer testing, regulatory authorization, and confirmation that the device remains safe for its intended clinical use. BD itself qualifies its update recommendations with the phrase "where available based on regulatory authorization."

**Operational availability:** Medical devices may be continuously involved in patient care. Taking hundreds of infusion pumps or monitors offline simultaneously for patching could create its own safety problem. Updates therefore have to be coordinated with Nursing, Biomedical Engineering, clinical leadership, device availability, spare-device capacity, and maintenance windows.

**Vendor dependency:** Firmware, configuration utilities, replacement components, and security fixes are frequently proprietary. MedDefense may need BD, Philips, Siemens, or another manufacturer to supply and approve a remediation rather than IT simply downloading and installing a generic patch. Vendor support timelines can therefore determine how quickly a known security weakness can actually be corrected.

**Long life cycles and interoperability:** Medical equipment commonly remains in service much longer than ordinary IT endpoints and must continue interoperating with PACS, EHR, central monitoring, wireless infrastructure, and specialized clinical software. Changing one component can therefore affect certification or interoperability elsewhere in the workflow. This is why compensating controls such as VLAN segmentation, ACLs, restricted management access, credential changes, and network monitoring are especially important for medical IoT.

## Conclusion

The MedDefense medical IoT problem is fundamentally an **architecture and patient-safety problem**, not just a collection of CVEs. The scan's attribution of CVE-2020-25165 to Alaris software 12.1.2 should be closed as an applicability false positive because BD states that 12.1.1 and newer address it. However, BD's later advisory confirms that the 12.1.2 generation has other genuine security weaknesses, while MedDefense has not implemented the vendor-recommended isolation model. Combined with broadly reachable IntelliVue interfaces and cleartext DICOM traffic, the environment allows compromise of an ordinary internal endpoint to place an attacker unnecessarily close to systems that monitor patients, deliver medication, and support diagnosis. The appropriate response is therefore a combination of **vendor-approved remediation, strong network segmentation, elimination of default credentials, restricted management access, and dedicated medical-device monitoring**.
