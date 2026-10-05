# Task 3 — Crimson Tide 72-Hour Emergency Response Plan

Advisory received 4 hours ago. Board convenes 09:00 tomorrow. Available now: Sarah Park plus **2 IT staff** tonight. Budget headroom: **$0** (the $120,000 Year-1 allocation is fully committed).

**Governing principle:** stop the *door*, then stop the *spread*, then stop the *loss*. Every Tier 1 action is free, reversible and does not require the Board; anything that costs money is deliberately pushed to Tier 2 where emergency approval can be sought.

---

## Tier 1 — Tonight (0–12 hours)

No budget, no procurement, minimal service-disruption risk.

### Action 1.1 — Verify the FortiOS version on the FortiGate
- **Phase Blocked:** Phase 1 (Initial Access)
- **Owner:** Sarah Park (or the on-call network tech under her direction)
- **Prerequisites:** Console or management access to `AST-043`; read-only command.
- **Risk of Action:** None — this is a read-only status check.
- **Risk of Inaction:** The entire response is built on an unknown. If the device is in the affected range, every other action below is being planned under a false assumption.

### Action 1.2 — Restrict external SSL-VPN exposure
- **Phase Blocked:** Phase 1
- **Owner:** Sarah Park
- **Prerequisites:** Version result from 1.1; inventory of staff currently relying on SSL-VPN.
- **Detail:** Disable the SSL-VPN web portal from the WAN, or restrict it to approved source addresses. **The site-to-site IPSec tunnels (Central↔Westside, Central↔HQ) are a separate service and must stay up** — hospital operations depend on them.
- **Risk of Action:** Remote and home-based staff lose SSL-VPN access until patched. Clinical systems at Central, Westside and HQ are unaffected because they use IPSec, not SSL-VPN.
- **Risk of Inaction:** If unpatched, this is a pre-authentication remote-code-execution path that **MFA cannot block**.

### Action 1.3 — Hunt the FortiGate logs for Crimson Tide IOCs
- **Phase Blocked:** Phase 1, Phase 2
- **Owner:** Sarah Park + second IT staff member
- **Prerequisites:** Preserve logs before any reboot or upgrade — do not let a firmware change destroy the evidence.
- **Detail:** Search for the advisory's URIs (`/remote/logincheck` with oversized payloads), non-standard User-Agent strings, unexpected VPN sessions, unusual CLI activity (`show system interface`), and any administrator or local account that cannot be explained by a change record.
- **Risk of Action:** None — read-only.
- **Risk of Inaction:** If the device is already compromised, we would patch a device the attacker still controls, and the dwell time (4–7 days in all five incidents) would continue unnoticed.

### Action 1.4 — Isolate NAS-01 by physical disconnection
- **Phase Blocked:** Phase 5 (Backup Destruction)
- **Owner:** Sarah Park + one IT staff member
- **Prerequisites:** Tonight's Veeam job must have **completed and been verified**; document the switch ports and cabling before unplugging; ensure local console access to DSM remains available.
- **Risk of Action:** No network backups while disconnected. If a production failure occurs overnight, the most recent restore point is the last verified set rather than tonight's.
- **Risk of Inaction:** The advisory confirms every one of the five victim hospitals had backup storage on the same network as production, and three had unencrypted backups that the attacker inspected before destroying them. NAS-01 matches all three conditions exactly.

### Action 1.5 — Verify the recovery path is real
- **Phase Blocked:** Phase 5, Phase 7
- **Owner:** Second IT staff member (parallel with 1.4)
- **Prerequisites:** Veeam catalog readable; scratch storage available.
- **Detail:** Confirm the most recent restore point is intact and the catalog is not corrupt; copy the Veeam configuration/catalog to separate offline media. MedDefense has never completed a full disaster-recovery test, so "we have backups" is an untested claim tonight.
- **Risk of Action:** Read-only plus a copy.
- **Risk of Inaction:** Discovering the recovery set is unusable *after* an encryption event converts a containable incident into a two-week outage.

### Action 1.6 — Audit privileged identity for attacker persistence
- **Phase Blocked:** Phase 2, Phase 3, Phase 6
- **Owner:** Sarah Park
- **Prerequisites:** AD access; awareness that disabling accounts can break services.
- **Detail:** Look for newly created Domain Admin or service accounts, unexpected group membership changes, and new GPOs outside a change window — the advisory's Phase 6 deploys ransomware by GPO from a compromised domain controller.
- **Risk of Action:** Disabling a legitimate service account breaks whatever uses it. Verify each account's purpose before touching it.
- **Risk of Inaction:** A compromised domain controller means the attacker's deployment mechanism is ready and the enterprise can be encrypted in hours.

### Action 1.7 — Freeze changes and increase outbound visibility
- **Phase Blocked:** Phase 4
- **Owner:** Network tech
- **Prerequisites:** FortiGate policy edit rights.
- **Detail:** Freeze all non-emergency change activity, enable/retain outbound session logging, and prepare (but do not rely on) blocks for the IOC destinations (Tor exit nodes, the abused cloud-storage service).
- **Risk of Action:** **Important caveat** — if the FortiGate is already compromised, its own blocking and logging are not trustworthy. Treat this as visibility, not as a control, until the device is verified.
- **Risk of Inaction:** Exfiltration of 15–65 GB is exactly the scale the advisory observed and MedDefense has no egress monitoring today (GAP-008).

---

## Tier 2 — Tomorrow (12–36 hours)

Requires coordination, a brief service window, and/or emergency Board approval.

### Action 2.1 — Emergency Board approval of the FortiGate support renewal
- **Phase Blocked:** Phase 1 (enabler for 2.2)
- **Owner:** James Chen (request) / CEO and Board (approve)
- **Prerequisites:** The version result from 1.1 showing the device is affected, or a decision to patch regardless.
- **Detail:** **$2,400** to renew the support contract, which is a prerequisite for downloading patched firmware.
- **Risk of Action:** Spending outside the approved budget requires Board authorization.
- **Risk of Inaction:** Without the contract, the only remaining mitigation is disabled SSL-VPN — which is acceptable temporarily but not sustainable.

### Action 2.2 — Patch the FortiGate
- **Phase Blocked:** Phase 1
- **Owner:** Sarah Park + external Fortinet partner
- **Prerequisites:** Contract renewed; full configuration backup exported and stored offline; correct upgrade path identified for the installed version; rollback firmware image available; **out-of-band console** access confirmed; maintenance window agreed with Clinical Operations.
- **Risk of Action:** A failed upgrade takes out MedDefense's only firewall and all three VPN tunnels simultaneously. There is no redundant perimeter device.
- **Risk of Inaction:** CVE-2023-27997 remains a public, KEV-listed, pre-authentication exploit path against a device whose compromise immediately exposes the entire flat internal network.

### Action 2.3 — Enforce MFA on VPN and administrative access
- **Phase Blocked:** Phase 2, Phase 3
- **Owner:** James Chen + Sarah Park
- **Prerequisites:** Existing O365 E3 licensing already provides the Entra ID capability (as established in the 1x03 analysis); user communication before enforcement.
- **Risk of Action:** Staff lockout on first login if enrolment is not staged; help-desk load spike.
- **Risk of Inaction:** It was captured VPN credentials — not cracking — that carried the attacker into internal systems in the advisory's chain.

### Action 2.4 — Remove weak Kerberos encryption and require LDAP signing
- **Phase Blocked:** Phase 3
- **Owner:** Sarah Park (execution) / James Chen (oversight)
- **Prerequisites:** **Dedicated maintenance window** — this can break authentication. Per the 1x02 remediation map: inventory unsigned LDAP binders first, stage on `ad-dc-02`, validate, then apply to `ad-dc-01`.
- **Risk of Action:** Legacy clinical applications and devices that hard-code RC4 or unsigned LDAP will fail to authenticate. This is a real clinical-availability risk, not a theoretical one.
- **Risk of Inaction:** The advisory reports Kerberoasting (RC4 tickets cracked offline) in 3 of 5 incidents. MedDefense has DES and RC4 enabled on both domain controllers today.

### Action 2.5 — Replace the NAS physical disconnect with enforced isolation
- **Phase Blocked:** Phase 5
- **Owner:** Network tech + Sarah Park
- **Prerequisites:** Documented backup traffic flows; dedicated backup-administration credentials separated from normal production identities.
- **Detail:** Move NAS-01 and `backup-srv-01` into a restricted backup zone with allow-list rules for Veeam traffic only, and restrict DSM management (TCP/5000/5001) to a management source. Keep the physical disconnection in place until this rule is proven working.
- **Risk of Action:** A wrong rule silently stops nightly backups — MedDefense has already suffered a multi-week backup gap from an untested change (GAP-018).
- **Risk of Inaction:** Reconnecting the NAS without isolation simply restores the exact configuration that all five victim hospitals had.

### Action 2.6 — Restrict EHR PostgreSQL to the application server
- **Phase Blocked:** Phase 4
- **Owner:** DBA + Sarah Park
- **Prerequisites:** Database backup; the application source address confirmed as `ehr-srv-01`; $4,000 already funded inside the segmentation line.
- **Risk of Action:** An incorrect `pg_hba.conf` allow-list takes the EHR down. Test with the application before removing the old rule.
- **Risk of Inaction:** The advisory's Phase 4 states the attacker copied raw database files without needing database credentials in 4 of 5 cases — which is possible at MedDefense precisely because the database is broadly reachable.

### Action 2.7 — Reset privileged credentials
- **Phase Blocked:** Phase 2, Phase 3
- **Owner:** Sarah Park
- **Prerequisites:** Staged, coordinated, off-hours to avoid lockouts; service-account dependencies mapped first.
- **Risk of Action:** Lockout of services using stale cached credentials.
- **Risk of Inaction:** Harvested credentials remain valid even after the FortiGate itself is patched.

---

## Tier 3 — This Week (36–72 hours)

Procurement, vendor involvement, or configuration that requires testing.

### Action 3.1 — Emergency network segmentation
- **Phase Blocked:** Phase 3 (the advisory's single most emphasised enabling factor)
- **Owner:** Sarah Park + 2 network techs + external vendor
- **Prerequisites:** Switch configuration changes require **2–3 days minimum**; ACL design from the 1x03 segmentation architecture; change management; clinical sign-off on medical-device flows.
- **Detail:** Minimum viable zones tonight: server, workstation, medical device, and management. The highest-value single rule is preventing general endpoints and VPN clients from reaching `ehr-db-01:5432`, AD administrative services, and backup management interfaces.
- **Risk of Action:** A misconfigured VLAN can take clinical systems offline during business hours.
- **Risk of Inaction:** In all five incidents the internal network was flat, and once inside the FortiGate the attacker had direct access to every system. Segmentation is the only control that limits blast radius regardless of how the attacker got in.

### Action 3.2 — Deploy server-class malware detection
- **Phase Blocked:** Phase 6
- **Owner:** Sarah Park + Sophos partner
- **Prerequisites:** Procurement/licensing; maintenance window for agent installation on servers. C-011 currently **excludes servers entirely**.
- **Risk of Action:** Agent installation may require reboots; potential performance impact on clinical workloads.
- **Risk of Inaction:** Ransomware deployment by GPO onto unprotected servers would be detected — if at all — by users noticing that systems stopped working.

### Action 3.3 — Stand up Wazuh with Crimson Tide detection content
- **Phase Blocked:** Phase 2, 3, 4, 6
- **Owner:** Security Analyst
- **Prerequisites:** Host and storage (already funded at $21,000); log sources from FortiGate, domain controllers, EHR and billing servers.
- **Detail:** Load the advisory's IOCs as the first detection rules: the ransomware payload hash, the modified Rclone hash, `vssadmin delete shadows`, new GPO creation outside change windows, Rclone appearing where it should not, and >5 GB outbound transfers.
- **Risk of Action:** Alert volume may exceed one analyst's capacity; tune rather than disable.
- **Risk of Inaction:** MedDefense's only demonstrated detection method is a user complaining about performance — the crypto-miner ran for at least two weeks that way.

### Action 3.4 — Encrypt backup sets and create an offsite immutable copy
- **Phase Blocked:** Phase 5
- **Owner:** Sarah Park / backup administrator
- **Prerequisites:** The key-management design from 1x04 Task 14 (HSM-backed KMS plus independent recovery project); additional storage for the immutable copy ($8,000 already funded).
- **Risk of Action:** Encryption extends the backup window; validate restore before cutting over.
- **Risk of Inaction:** Unencrypted backups let the attacker verify they hold valuable data before destroying them — observed in 3 of 5 incidents.

### Action 3.5 — Incident-response tabletop and plan update
- **Phase Blocked:** Phase 7
- **Owner:** James Chen
- **Prerequisites:** Stakeholder time (executive, legal, clinical, communications); the SANS six-step framework referenced in the course resources.
- **Detail:** Walk the exact Crimson Tide chain against MedDefense, including the extortion phase — who decides on payment, who talks to the FBI, who notifies patients, and who speaks publicly.
- **Risk of Action:** None.
- **Risk of Inaction:** GAP-012 means there is currently no formal IR process, no defined recovery priorities and no communications procedure, while the advisory shows a 96-hour extortion deadline.

### Action 3.6 — Patch the remaining Critical server-side findings
- **Phase Blocked:** Phase 1, Phase 6
- **Owner:** Sarah Park
- **Prerequisites:** Maintenance windows; already-funded remediation items.
- **Detail:** Apache mod_lua RCE and privilege escalation on `billing-srv-01` (Findings 001/002); Ubuntu 18.04 ESM gap (Finding 011).
- **Risk of Action:** Standard patch risk on a production billing server.
- **Risk of Inaction:** A second, independent remote-entry path into the environment remains open while all attention is on the FortiGate.

---

## Resource Conflict Assessment

**Conflict 1 — Sarah is a single point of failure.** She is the only person who can act on the FortiGate, AD, the NAS and the DBA relationship. Tier 1 alone assigns her four actions and Tier 2 assigns her five more.
**Resolution:** Sequence strictly by risk reduction, not by convenience — FortiGate (1.1, 1.2) first, because it is the door. Delegate NAS isolation (1.4) and recovery verification (1.5) entirely to the two IT staff. Delegate AD analysis to James with Sarah validating only the change itself. Use the external Fortinet partner for the firmware upgrade so Sarah can run the identity work in parallel.

**Conflict 2 — One FortiGate, five competing changes.** The device needs a version check, an SSL-VPN restriction, egress rules, MFA configuration, and a firmware patch.
**Resolution:** Strictly sequential. Read-only checks first (1.1, 1.3). Then the reversible *service* restriction (1.2), which does not alter the security policy engine. Then MFA (2.3). Then the egress visibility change (1.7). The firmware patch (2.2) goes **last and alone**, with a configuration backup taken immediately before it. Never combine the patch with any other change.

**Conflict 3 — NAS disconnection versus tonight's backup.** Disconnecting before the job finishes forfeits a night of protection.
**Resolution:** Let tonight's Veeam job complete, verify it (1.5), then disconnect (1.4). If the job runs past the point where the team must stop, disconnect anyway and document the one-night gap — an isolated older backup is worth more than a current but reachable one.

**Conflict 4 — AD Kerberos changes versus VPN/SSL changes.** Both need Sarah, both can break authentication, and running them in the same window would make the cause of any failure ambiguous.
**Resolution:** Separate windows, at least one day apart. AD changes go to Tier 2/3, staged `ad-dc-02` before `ad-dc-01`, per the existing remediation map. If a legacy clinical dependency fails, isolate it under a documented, time-limited, source-scoped exception rather than reverting the whole domain to RC4.

**Conflict 5 — Emergency spend versus a fully committed budget.** The $120,000 is allocated and the support renewal is unbudgeted.
**Resolution:** Keep Tier 1 entirely free so no approval blocks immediate risk reduction. Present the Board with a single decision: approve **$2,400** now for the patch, or accept continued pre-authentication exposure behind a disabled SSL-VPN portal. Everything else in Tier 3 is either already funded or deferred to the accelerated roadmap.

**Conflict 6 — No redundant perimeter.** If the FortiGate upgrade fails there is no fallback device.
**Resolution:** Out-of-band console access, an offline configuration export, a validated rollback image, and the vendor on the call before the window opens. If any of those four is missing, the window does not open.
