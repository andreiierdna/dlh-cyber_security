# Task 6 — Technical Proof

**Lab:** Kali Linux (rolling), kernel `6.19.14+kali-arm64`, accessed over SSH on 2026-10-05.
**Tools:** OpenSSL 3.6.2 · `sha256sum` · searchsploit (exploitdb `20260904-0kali1`) · Lynis 3.1.6.

---

## Check 1 — Certificate Inspection

```bash
echo | openssl s_client -connect www.cloudflare.com:443 -servername www.cloudflare.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

echo | openssl s_client -connect www.cloudflare.com:443 -servername www.cloudflare.com 2>/dev/null \
  | openssl x509 -noout -text | grep -E "Public Key Algorithm|Public-Key:|NIST CURVE"
```

```text
subject=CN=www.cloudflare.com
issuer=C=US, O=Google Trust Services, CN=WE1
notBefore=Sep 16 13:01:15 2026 GMT
notAfter=Dec 15 14:00:55 2026 GMT
X509v3 Subject Alternative Name:
    DNS:www.cloudflare.com, DNS:timeline.www.cloudflare.com
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                NIST CURVE: P-256
```

**Summary:**

1. **Subject:** `CN=www.cloudflare.com`
2. **Issuer:** Google Trust Services, `CN=WE1`
3. **Validity:** 2026-09-16 → 2026-12-15 (90 days)
4. **Key Algorithm:** ECDSA (`id-ecPublicKey`), 256-bit, curve P-256
5. **SAN entries:** `www.cloudflare.com`, `timeline.www.cloudflare.com`

---

## Check 2 — Hash Verification

```bash
echo "MedDefense FortiGate firmware integrity test v1" > firmware_test.txt
sha256sum firmware_test.txt | tee before.sha256
echo "unauthorized modification" >> firmware_test.txt
sha256sum firmware_test.txt | tee after.sha256
[ "$(cut -d' ' -f1 before.sha256)" != "$(cut -d' ' -f1 after.sha256)" ] && echo "RESULT: hashes differ"
```

```text
cc07edbe688388c939be50726191b0c29bd9a5e78da45874ef0f78a2efc9f196  firmware_test.txt
1aa8de5d318c0210be20b9f3152174fdb0b79aeedd933394edc82249ce2ea2e9  firmware_test.txt
RESULT: hashes differ
```

**Confirmed:** one appended line produced a completely different digest.

**Why it matters for the FortiGate firmware:** matching the downloaded image's SHA-256 against the value Fortinet publishes proves the file was not corrupted or tampered with in transit, so MedDefense does not install attacker-modified firmware on the one device that protects its entire network.

---

## Check 3 — Exploit Research

```bash
searchsploit fortigate
searchsploit fortios
searchsploit --cve 2023-27997
```

**`searchsploit fortigate`** (11 results):

```text
Fortigate Firewall 2.x - dlg Admin Interface  | hardware/remote/23376.txt
Fortigate Firewall 2.x - listdel Admin Interf | hardware/remote/23378.txt
Fortigate Firewall 2.x - Policy Admin Interfa | hardware/remote/23377.txt
Fortigate Firewall 2.x - selector Admin Inter | hardware/remote/23379.txt
Fortigate Firewalls - 'EGREGIOUSBLUNDER' Remo | hardware/webapps/40276.txt
Fortigate Firewalls - Cross-Site Request Forg | hardware/webapps/26528.txt
Fortigate UTM WAF Appliance - Multiple Vulner | hardware/webapps/21395.txt
Fortinet Fortigate - CRLF Characters URL Filt | hardware/remote/31026.pl
Fortinet Fortigate 2.x/3.0 - URL Filtering By | hardware/remote/27203.pl
Fortinet FortiGate 4.x < 5.0.7 - SSH Backdoor | linux/remote/43386.py
Fortinet FortiGate FortiOS < 6.0.3 - LDAP Cre | hardware/webapps/46171.py
```

**`searchsploit fortios`** (8 results):

```text
Fortinet FortiGate FortiOS < 6.0.3 - LDAP Cre | hardware/webapps/46171.py
Fortinet FortiOS 5.6.3 - 5.6.7 / FortiOS 6.0. | hardware/webapps/47287.rb
Fortinet FortiOS 5.6.3 - 5.6.7 / FortiOS 6.0. | hardware/webapps/47288.py
Fortinet FortiOS 6.0.4 - Unauthenticated SSL  | hardware/webapps/49074.py
Fortinet FortiOS < 5.6.0 - Cross-Site Scripti | hardware/webapps/42388.txt
Fortinet FortiOS_ FortiProxy_ and FortiSwitch | windows/remote/52239.py
FortiOS SSL-VPN 7.4.4 - Insufficient Session  | multiple/remote/52336.py
FortiOS_ FortiProxy_ FortiSwitchManager v7.2. | multiple/webapps/51092.sh
```

**`searchsploit --cve 2023-27997`:**

```text
Exploits: No Results
Shellcodes: No Results
Papers: No Results
```

**Is there a public exploit for CVE-2023-27997?** Not in Exploit-DB — `searchsploit -j` maps the 18 unique entries to older CVEs (for example CVE-2018-13379, CVE-2022-40684), and there is no merged Metasploit module ([rapid7 #18163](https://github.com/rapid7/metasploit-framework/issues/18163)). **But public exploit code does exist elsewhere** (for example [Lexfo's xortigate research](https://github.com/lexfo/xortigate-cve-2023-27997)), and NVD records the CVE in the **CISA KEV catalog since 2023-06-13**, which confirms real-world exploitation.

**Urgency:** a missing Exploit-DB entry is not reassurance. This is a pre-authentication, KEV-listed bug on MedDefense's only firewall, actively used by Crimson Tide; Exploit-DB also already holds working exploits for earlier FortiOS SSL-VPN flaws (CVE-2018-13379), showing these bugs are weaponised quickly. **Patch immediately; until then, restrict SSL-VPN access.**

---

## Check 4 — System Audit

```bash
sudo lynis audit system --quick
```

```text
Warnings (2):
  ! apt-get check returned a non successful exit code. [PKGS-7390]
  ! Nameserver 0.100.100.100 does not respond [NETW-2704]

Suggestions (59)

Hardening index : 62 [############        ]
Tests performed : 273
```

**Hardening Index: 62 / 100.**

**Top 3 warnings.** Lynis raised only **two** summary warnings; the third is the most security-relevant `[ WARNING ]` from the test body:

| # | ID | Finding | Why it matters |
|---|---|---|---|
| 1 | PKGS-7390 | `apt-get check` failed — package database inconsistent | Patch state cannot be trusted; mirrors MedDefense GAP-011 (no patch management). |
| 2 | NETW-2704 | Configured nameserver `0.100.100.100` does not respond | Broken DNS dependency that would surface as an unexplained outage. |
| 3 | AUTH-9252 | `/etc/sudoers.d` permissions flagged (`755`, verified with `stat`) | Privilege configuration is world-readable; tighten to `750`. |

**Suggestion for `billing-srv-01` — DEB-0880: install `fail2ban`.**

| Link | Trace |
|---|---|
| Threat | Crimson Tide Phase 3 — SSH to Linux servers |
| Vulnerability | 1x02 **Finding 009** — password SSH with no lockout on `billing-srv-01` |
| Gap | 1x00 **GAP-008** — billing server lacks server-class protection |
| Control | Complements 1x03 **MFA** ($10,000) and feeds **Wazuh SIEM** ($21,000) |
| Cost | **$0** licensing (open source); about one hour of admin time |

**Assumption / limit:** fail2ban stops password guessing, not logins with credentials already harvested from the FortiGate. It is a quick win, not a substitute for key-only SSH, MFA and segmentation.
