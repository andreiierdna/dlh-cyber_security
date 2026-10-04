# Task 11 — The TLS Audit

## Scope

This audit compares two current public SSL Labs reports, predicts the posture of MedDefense's internal patient portal, and provides a hardened Apache configuration. Public results can change as sites rotate certificates or alter edge configurations.

## Part 1 — SSL Labs Analysis

Sources: [Cloudflare SSL Labs report](https://www.ssllabs.com/ssltest/analyze.html?d=www.cloudflare.com), [Amazon India SSL Labs report](https://www.ssllabs.com/ssltest/analyze.html?d=www.amazon.in), and the [SSL Labs rating guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide). The captured API reports used SSL Labs engine 2.4.3 and criteria 2009q.

### Site 1: `www.cloudflare.com` — A+

All tested IPv4 and IPv6 endpoints received **A+**.

| Item | SSL Labs result | Assessment |
|---|---|---|
| **Protocols** | TLS 1.2 and TLS 1.3; no TLS 1.0/1.1 | Strong modern baseline. |
| **Key exchange** | ECDHE with X25519/P-256-class groups; reported strength approximately equivalent to RSA 3072 | Forward secrecy is available to all simulated clients. |
| **TLS 1.3 ciphers** | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` | AEAD-only and strong. |
| **TLS 1.2 ciphers** | ECDHE with AES-GCM or ChaCha20-Poly1305, plus some CBC/static-RSA compatibility suites | Modern clients negotiate strong suites, but the compatibility suites are unnecessary for MedDefense. |
| **HSTS** | Present: `max-age=31536000; includeSubDomains` | One-year policy contributes to the A+ posture. |
| **Warnings** | Endpoint warning flag: false | No grade-reducing warning; SSL Labs still labels several legacy TLS 1.2 compatibility suites weak. |

**Certificate observed:** `CN=www.cloudflare.com`; SANs include `www.cloudflare.com`; Google Trust Services `WE1` issuer; ECDSA P-256 public key; `ecdsa-with-SHA256` signature; valid from **2026-09-16** to **2026-12-15**; trusted chain and Certificate Transparency records present.

**Lesson for MedDefense:** A strong grade comes from the complete policy—modern protocols, forward-secret AEAD suites, a trusted certificate, and HSTS—not from a single strong cipher.

### Site 2: `www.amazon.in` — B

All tested endpoints received **B**.

| Item | SSL Labs result | Assessment |
|---|---|---|
| **Protocols** | TLS 1.0, 1.1, 1.2, and 1.3 | TLS 1.0/1.1 cap the grade at B under criteria 2009q. |
| **Key exchange** | ECDHE/X25519 at approximately RSA-3072-equivalent strength for modern clients; static RSA suites also enabled | Modern clients receive forward secrecy, but not every supported path does. |
| **Strong ciphers** | TLS 1.3 AES-GCM/ChaCha20-Poly1305 and TLS 1.2 ECDHE-AES-GCM/ChaCha20 | Strong options exist. |
| **Weak ciphers** | AES-CBC, static-RSA suites, and `TLS_RSA_WITH_3DES_EDE_CBC_SHA` (112-bit) on legacy protocols | A client can negotiate weaker protection than necessary. |
| **HSTS** | Absent in the captured report | Removes browser-enforced HTTPS persistence and prevents an A+ posture. |
| **Warnings** | Endpoint warning flag: false | The B grade is caused by supported legacy protocols; weak suites remain visible in the detailed report. |

**Certificate observed:** `CN=www.amazon.in`; SANs include `amazon.in`, `amazon.co.in`, and their `www` names; GeoTrust TLS RSA CA G1 issuer; RSA-2048 public key; `sha256WithRSAEncryption` signature; valid from **2026-09-03** to **2027-03-19**; trusted chain, OCSP URL, and Certificate Transparency records present.

**Lesson for MedDefense:** Adding TLS 1.3 does not compensate for leaving TLS 1.0, TLS 1.1, 3DES, CBC, or static-RSA negotiation enabled.

## Part 2 — MedDefense Portal Assessment

**Predicted SSL Labs grade: B at best.** Finding 005 confirms TLS 1.0 and TLS 1.2, so the legacy-protocol rule caps the portal at B even if its certificate and ciphers are otherwise sound. The actual grade could be lower because the scan did not inventory the portal's full cipher suite or key-exchange configuration.

### Grade-impacting issues

| Issue | Evidence | Likely effect |
|---|---|---|
| TLS 1.0 enabled | Finding 005 | Caps the grade at B and permits obsolete protocol behavior. |
| TLS 1.3 absent/not evidenced | Finding 005 documents only TLS 1.0 and 1.2 | Current SSL Labs criteria warn and cap otherwise strong servers below A when TLS 1.3 is absent. |
| HSTS missing | Finding 012 | Prevents A+ and leaves first-contact HTTP downgrade exposure. |
| Cipher policy unknown | Default Apache configuration; no suite inventory | CBC, 3DES, static RSA, or lack of forward secrecy could reduce the grade further. |
| Certificate near expiry | Finding 013: 23 days remaining | While valid, short remaining life does not itself lower the cryptographic score; expiration would make the certificate untrusted and fail normal browser access. |

### Operational issues not directly scored

- No automated certificate renewal, making expiry recurrence likely.
- OCSP stapling is not documented.
- Other missing headers from Finding 012 and HTTP TRACE from Finding 021 matter to web security, but are not substitutes for TLS hardening.

### Remediation order

1. Renew the certificate and automate renewal before the current certificate expires.
2. Disable TLS 1.0/1.1 and permit only TLS 1.2/1.3.
3. Restrict TLS 1.2 to ECDHE plus AEAD ciphers; remove CBC, 3DES, RC4, and static RSA.
4. Enable HSTS after confirming the portal and included subdomains work exclusively over HTTPS.
5. Validate with `apachectl configtest`, protocol-specific `openssl s_client` checks, and SSL Labs after public deployment.

## Part 3 — Hardened Apache Configuration

Requires Apache 2.4 with `mod_ssl`, `mod_headers`, and OpenSSL 1.1.1 or newer. Certificate paths are the proposed managed locations on `web-srv-01`.

```apache
# Server-wide OCSP cache
SSLStaplingCache shmcb:/var/run/apache2/ocsp_stapling(128000)

<VirtualHost *:80>
    ServerName portal.meddefense.local
    Redirect permanent / https://portal.meddefense.local/
</VirtualHost>

<VirtualHost *:443>
    ServerName portal.meddefense.local
    DocumentRoot /var/www/portal

    SSLEngine On
    SSLCertificateFile /etc/ssl/certs/portal-meddefense-fullchain.pem
    SSLCertificateKeyFile /etc/ssl/private/portal-meddefense.key

    # TLS 1.2 and 1.3 only
    SSLProtocol -all +TLSv1.2 +TLSv1.3

    # TLS 1.3 preference order
    SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256

    # TLS 1.2: ECDHE forward secrecy and AEAD only
    SSLCipherSuite SSL ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder On
    SSLOpenSSLConfCmd Curves X25519:P-256:P-384

    SSLCompression Off
    SSLSessionTickets Off
    SSLInsecureRenegotiation Off

    SSLUseStapling On
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors Off

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</VirtualHost>
```

### Why each choice

| Choice | Reason |
|---|---|
| `TLSv1.2` and `TLSv1.3` only | Preserves modern compatibility while removing the TLS 1.0 weakness in Finding 005. |
| `TLS_AES_256_GCM_SHA384` | Preferred TLS 1.3 AES option with 256-bit authenticated encryption. |
| `TLS_CHACHA20_POLY1305_SHA256` | Strong AEAD alternative that performs well on clients without AES hardware acceleration. |
| `TLS_AES_128_GCM_SHA256` | Strong, efficient TLS 1.3 fallback with broad implementation support. |
| TLS 1.2 `ECDHE-*` suites | ECDHE provides forward secrecy; RSA and ECDSA variants allow either approved certificate type. |
| AES-GCM and ChaCha20-Poly1305 only | AEAD protects confidentiality and integrity without CBC padding weaknesses. |
| `SSLHonorCipherOrder On` | Makes Apache's TLS 1.2 order authoritative instead of accepting a weaker client preference. |
| `X25519:P-256:P-384` | Limits ephemeral key exchange to modern, interoperable elliptic-curve groups. |
| Compression off | Prevents TLS compression attacks such as CRIME. |
| Session tickets off | Avoids long-lived ticket keys weakening forward secrecy when ticket-key rotation is not managed. |
| Insecure renegotiation off | Rejects obsolete renegotiation behavior while secure renegotiation remains available. |
| OCSP stapling | Lets Apache provide certificate status during the handshake when the issuing CA offers OCSP. |
| HSTS for one year | Forces returning browsers to use HTTPS; `includeSubDomains` must be enabled only after every subdomain supports HTTPS. |
| No `preload` initially | Preload is difficult to reverse and should follow successful organization-wide HTTPS validation. |
| Automated renewal and monitoring | Prevents Finding 013 from becoming an expired-certificate outage; alert before renewal failure reaches the expiry window. |

### Deployment validation

```bash
sudo apachectl configtest
sudo systemctl reload apache2

# Must fail
openssl s_client -connect portal.meddefense.local:443 -servername portal.meddefense.local -tls1
openssl s_client -connect portal.meddefense.local:443 -servername portal.meddefense.local -tls1_1

# Must succeed with an approved AEAD cipher
openssl s_client -connect portal.meddefense.local:443 -servername portal.meddefense.local -tls1_2
openssl s_client -connect portal.meddefense.local:443 -servername portal.meddefense.local -tls1_3

curl -fsSI https://portal.meddefense.local/
```

Confirm the certificate chain and hostname, TLS 1.2/1.3 negotiation, approved ciphers, HSTS on success and error responses, portal login, patient-record access, and automated-renewal dry run before closing Findings 005, 012, and 013.

## Part 4 — The Downgrade Attack

A network attacker attempts a TLS downgrade by interfering with the initial handshake so the client and server do not complete their strongest mutually supported protocol. When an older fallback-capable client retries after the attacker drops its TLS 1.2 attempt, the server's continued TLS 1.0 support allows a weaker TLS 1.0 session instead. Modern handshake protections prevent simple version-field rewriting, and HSTS addresses HTTP-to-HTTPS downgrade rather than making TLS 1.0 safe. The simplest prevention is to disable TLS 1.0 and TLS 1.1 server-side and accept only TLS 1.2 and TLS 1.3.

## References

- [Qualys SSL Labs API](https://www.ssllabs.com/projects/ssllabs-apis/index.html)
- [SSL Labs SSL Server Rating Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)
- [Apache `mod_ssl` documentation](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html)
- [Apache `mod_headers` documentation](https://httpd.apache.org/docs/2.4/mod/mod_headers.html)
- [MedDefense Finding 005, 012, 013, and 021](../1x02_the_weak_links/13-web_exposure.md)
