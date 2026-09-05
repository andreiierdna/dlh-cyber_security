# Security Incident Analysis: billing-srv-01 Root Cause Assessment

## 1. Process Identification: What Is Actually Running

The process identified as PID 8834 is not a legitimate system process, despite its name. This is established by three independent indicators in the diagnostics:

- **Execution path:** `/proc/8834/exe` resolves to `/var/www/html/.cache/kworker`. Legitimate `kworker` threads are part of the Linux kernel's worker-thread pool. They execute from kernel space, are always displayed with square brackets (e.g., `[kworker/0:1]`), and run as `root` with no associated executable on disk. A `kworker` binary sitting in a web server's cache directory, executable and owned by `www-data`, is a filename chosen specifically to blend into a `top` listing and evade casual review.
- **Command-line arguments:** The process is invoked with `-o stratum+tcp://pool.monero.org:4443 --threads 4 --donate-level 0`. The `stratum` protocol is the standard communication protocol used by cryptocurrency mining pools to distribute work units to miners and collect submitted shares. `pool.monero.org` is a public mining pool for Monero (XMR), a cryptocurrency favored in illicit mining operations because its protocol obscures wallet-to-transaction linkage. The `config.json` file recovered from the same directory confirms this: it lists three pool endpoints and a wallet address, and explicitly sets `"donate-level": 0` — the operator has disabled the small "developer support" tax that mining software normally contributes, indicating a deliberately configured, self-interested deployment rather than an accidental install.
- **Network behavior:** The `netstat` output shows three concurrent outbound connections from this process to the ports specified in the pool configuration (`4443`, `8080`, `3333`), all in `ESTABLISHED` state and consuming sustained bandwidth. This matches the behavioral signature of active mining: constant outbound traffic to pool infrastructure with no corresponding inbound service request, unlike Apache or MySQL, which show connections tied to defined listening ports.

**Conclusion:** PID 8834 is unauthorized cryptomining malware (a "cryptojacker") running under the `www-data` service account, using process-name spoofing to disguise itself as a legitimate kernel thread. It is consuming CPU cycles to generate Monero for an external, unknown party.

---

## 2. Classifying the Real Compromise: CIA Impact Before Availability

The sysadmin's ticket frames this purely as an Availability problem ("CPU saturation," "billing app is slow"). That framing is a description of the *symptom*, not the *incident*. Two more severe violations occurred earlier in the attack chain and are the actual root cause:

**a) Integrity — Compromised.** The presence of an unauthorized, attacker-controlled executable running under the web server's service account means the underlying system state has been altered without authorization. `www-data` should only ever execute the Apache binary and its configured application code; here it is executing a foreign binary planted by a third party. Once an attacker has achieved arbitrary code execution as `www-data`, they have write access to any file or directory that account can reach — which, on a typical LAMP deployment, includes the web application's document root, and potentially the billing application's source code and configuration files. The system can no longer be trusted to be running only the software MedDefense's IT team deployed. This is an Integrity violation because the trustworthiness and known-good state of the server has been broken, independent of whether performance was affected.

**b) Confidentiality — Compromised (or at minimum, unverified and must be presumed compromised).** Remote code execution as `www-data` provides the attacker read access to everything that account can read: the billing application's database connection strings, session tokens, and — critically — MySQL is running on this same host (PID 1455, listening on 3306) and is reachable from the same compromised context. Depending on credential storage in the application config, the attacker may have had a direct path to the billing database itself, which under a healthcare organization's threat model likely contains patient billing records tied to protected health information (PHI). Even without direct evidence of exfiltration in this diagnostic snapshot, the standard of assumption in incident response is that any data reachable by a compromised account must be treated as potentially disclosed until forensic evidence proves otherwise.

**Availability** — the CPU saturation Tom observed — is the *last* and least severe link in this chain. It is also, unfortunately, the only one visible to someone looking at `top` without asking "why is a process named kworker running as www-data from a web directory."

---

## 3. Why the Sysadmin's Solution Fails

Upgrading billing-srv-01 to a 16GB RAM / 8-vCPU VM would not remove the malware — it would only make the malware run more efficiently.

The mining software installed at `/var/www/html/.cache/kworker` is configured with `"threads": 4`, matching the current 4-vCPU allocation. On more powerful hardware, the miner would either be reconfigured (by whatever mechanism reinstalled it) or would simply autoscale its thread count to consume the newly available cores, since cryptomining workloads are designed to consume all CPU capacity made available to them. The billing application would see the same relative resource starvation on the new VM within a similar timeframe, and the same three-strikes pattern of "restart, temporary relief, recurrence" would repeat, because a hardware migration does nothing to:

- Remove the planted binary and its persistence mechanism (unknown from this data — likely a cron job, systemd service, or web shell re-dropping the payload, since the file's `Access`/`Modify`/`Change` timestamps are 14 days old, predating the current 12-day uptime and surviving at least one prior reboot).
- Close the initial access vector that allowed the attacker onto the server in the first place.
- Revoke any credentials, sessions, or database access the attacker may have obtained during the compromise window.

Migrating hardware without remediating the compromise is equivalent to renovating a house while leaving a duplicate key with the burglar — the underlying access path remains open, and the new environment simply gives the intruder more room to work in.

---

## 4. Connection to the January Ransomware Incident

Marcus's note states that billing-srv-01 was rebuilt following a ransomware incident in January, and that the performance-degradation pattern reportedly began *before* the ransomware event and has now resumed *after* the rebuild, on the same host, via what is likely the same entry point with a different payload.

This is a materially significant finding for two reasons:

- **The rebuild did not eliminate the vulnerability.** A server rebuild that restores the same OS version (Ubuntu 18.04.6, which Marcus notes is approaching end-of-life) and the same Apache version (2.4.29, which Marcus flags as having known unpatched RCE vulnerabilities) reintroduces the same weakness that allowed the January compromise. If the rebuild process is a golden image or a documented configuration baseline that has not been updated to patch this vulnerability, every future rebuild will produce another exploitable server. The rebuild addressed the *symptom* of the January incident (encrypted/damaged data) without addressing its *cause* (the vulnerable software stack).
- **Two distinct attackers (or the same attacker with two different objectives) exploited the same entry point.** Ransomware and cryptomining are different monetization strategies but require the same initial foothold: unauthenticated or lightly-authenticated remote code execution against the web-facing application. That this server has now been compromised twice via what appears to be the same class of vulnerability indicates the entry point itself — not the server's hardware, and not any single payload — is the organization's actual unresolved risk.

**The question that must now be asked, and escalated to James Chen and MedDefense leadership, is:** *Was the specific vulnerability that enabled the January ransomware incident (the suspected Apache 2.4.29 RCE) formally identified, documented, and remediated as part of the incident response process — or was the server simply restored from a backup/image and returned to production without a patch verification step?* If the latter, this is not a two-time coincidence; it is evidence of a gap in MedDefense's incident response lifecycle (specifically, the "eradication" and "lessons learned" phases), and every other server built from the same image or running the same Apache version should be presumed equally exposed until verified otherwise.
