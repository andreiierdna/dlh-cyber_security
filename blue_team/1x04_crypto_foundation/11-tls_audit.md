# Task 11 — The TLS Audit

## Goal

Evaluate real-world TLS configurations using Qualys SSL Labs, compare a strong configuration against a weaker one, assess the current MedDefense patient portal, and design a hardened TLS configuration that supports only modern protocols and cipher suites.

---

# Executive Summary

TLS protects patient information while it travels between a patient's browser and the MedDefense portal. A secure deployment requires more than simply enabling HTTPS: the server must use current TLS versions, strong authenticated cipher suites, forward-secret key exchange, a valid certificate, appropriate security headers, and safe session-management settings.

The MedDefense vulnerability scan identified three directly related weaknesses on `web-srv-01`:

- **Finding 005:** TLS 1.0 remains enabled alongside TLS 1.2.
- **Finding 012:** HTTP Strict Transport Security (HSTS) is missing.
- **Finding 013:** The patient-portal certificate is close to expiration and has no automated renewal.

Finding 005 specifically reports TLS 1.0 and TLS 1.2 support and recommends disabling TLS 1.0/1.1 and enabling TLS 1.3. Finding 012 confirms that HSTS and other security headers are absent. Finding 013 states that the portal certificate expires in 23 days and that automatic renewal is not configured.

---

# Part 1 — SSL Labs Analysis

## Websites Selected

Two real public websites were examined using **Qualys SSL Labs**:

| Website | Purpose | SSL Labs Grade |
|---|---|---:|
| **www.mychart.org** | Strong healthcare-related TLS example | **A+** |
| **www.amazon.in** | Example with legacy protocol support | **B** |

The exact grade of a public website can change as its TLS configuration changes, so these results represent the SSL Labs assessments available during this project.

---

# Site 1 — www.mychart.org

## Overall Grade

# **A+**

SSL Labs assessed `www.mychart.org` with an **A+** rating. The report shows TLS 1.2 and TLS 1.3 support, long-duration HSTS, forward secrecy, and a trusted certificate.

---

## Protocol Support

| Protocol | Supported? |
|---|---:|
| SSL 2.0 | ❌ No |
| SSL 3.0 | ❌ No |
| TLS 1.0 | ❌ No |
| TLS 1.1 | ❌ No |
| **TLS 1.2** | ✅ Yes |
| **TLS 1.3** | ✅ Yes |

This is the protocol model MedDefense should follow.

Qualys recommends TLS 1.2 as the minimum supported protocol with TLS 1.3 enabled when available, while TLS 1.0 and TLS 1.1 should be avoided.

---

## Key Exchange Strength

The MyChart configuration uses ephemeral elliptic-curve Diffie-Hellman.

Example:

```text
ECDH secp256r1
≈ 3072-bit RSA equivalent
Forward Secrecy: Yes
```

This provides **forward secrecy**, meaning compromise of the server's long-term private key does not automatically expose previously recorded TLS sessions.

---

## Cipher Suite Strength

### TLS 1.3

The preferred suites include:

```text
TLS_AES_256_GCM_SHA384
TLS_AES_128_GCM_SHA256
```

Both are modern authenticated-encryption suites.

### TLS 1.2

Strong suites include:

```text
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

These combine:

```text
ECDHE
   │
   └── Forward-secret key exchange

AES-GCM
   │
   └── Authenticated encryption

SHA-256 / SHA-384
   │
   └── Cryptographic hashing / PRF
```

The report also exposes an AES-CBC fallback suite that SSL Labs labels weak, but the overall deployment still receives an A+ because the modern protocol and security posture are strong.

---

## Certificate Details

| Property | Value |
|---|---|
| Subject | `www.mychart.org` |
| Public Key | RSA 2048-bit |
| Signature | SHA256withRSA |
| Issuer | GeoTrust TLS RSA CA G1 |
| Valid From | May 18, 2026 |
| Valid Until | November 18, 2026 |
| Trust | Trusted |
| Revocation Status | Good |

The certificate chains to a trusted DigiCert root and had no reported trust failure.

---

## Other Security Features

```text
Forward Secrecy             YES
HSTS                        YES
TLS Compression             NO
RC4                         NO
Heartbleed                  NO
ROBOT                       NO
Insecure Renegotiation      NO
Downgrade Protection        YES
```

HSTS is configured as:

```text
max-age=31536000; includeSubDomains; preload
```

This tells compliant browsers to access the site only through HTTPS for one year.

---

## Warnings / Weaknesses

Although the deployment receives an A+, SSL Labs notes several non-critical observations:

- OCSP stapling is not enabled.
- Post-quantum key exchange was not supported in the cited assessment.
- Some older clients require SNI.
- A TLS 1.2 CBC fallback cipher remains available.

None of these prevented the A+ grade in the assessed configuration.

---

# Site 2 — www.amazon.in

## Overall Grade

# **B**

SSL Labs reports a **B** grade for the tested Amazon India endpoint.

The principal reason is straightforward:

> The server continues to support TLS 1.0 and TLS 1.1.

SSL Labs explicitly caps servers supporting either TLS 1.0 or TLS 1.1 at **B**, even when modern TLS versions are also available.

---

## Protocol Support

| Protocol | Supported? |
|---|---:|
| SSL 2.0 | ❌ No |
| SSL 3.0 | ❌ No |
| **TLS 1.0** | ⚠️ Yes |
| **TLS 1.1** | ⚠️ Yes |
| **TLS 1.2** | ✅ Yes |
| **TLS 1.3** | ✅ Yes |

This is an excellent comparison for MedDefense.

A server may support excellent TLS 1.3 encryption but still weaken its security posture by maintaining compatibility with obsolete protocols.

---

## Key Exchange Strength

Modern connections use strong ephemeral key establishment.

TLS 1.3 includes a hybrid key-exchange group reported as:

```text
X25519MLKEM768
```

while TLS 1.2 uses:

```text
ECDHE
X25519
≈ 3072-bit RSA equivalent
Forward Secrecy: Yes
```

The key-exchange strength itself is therefore not the principal reason for the B rating.

---

## Cipher Suite Strength

The server supports modern suites such as:

```text
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
```

and TLS 1.2 suites such as:

```text
ECDHE-RSA-AES128-GCM-SHA256
ECDHE-RSA-AES256-GCM-SHA384
ECDHE-RSA-CHACHA20-POLY1305
```

However, the configuration also maintains legacy CBC and, on some tested endpoints, 3DES-compatible suites.

Examples include:

```text
ECDHE-RSA-AES128-CBC-SHA
ECDHE-RSA-AES256-CBC-SHA
RSA-AES128-CBC-SHA
3DES-EDE-CBC-SHA
```

SSL Labs marks several of these as **WEAK**.

---

## Certificate Details

| Property | Value |
|---|---|
| Subject | `www.amazon.in` |
| Public Key | RSA 2048-bit |
| Signature Algorithm | SHA256withRSA |
| Issuer | GeoTrust TLS RSA CA G1 |
| Valid From | September 3, 2026 |
| Valid Until | March 19, 2027 |
| Trust | Trusted |
| Certificate Transparency | Yes |

The certificate itself is not the cause of the reduced grade.

---

## Primary Weaknesses

The B rating demonstrates an important lesson:

```text
Strong certificate
       +
Strong TLS 1.3
       +
Strong ECDHE key exchange
       +
Strong AES-GCM
       ≠
Perfect TLS configuration
```

because:

```text
TLS 1.0 / TLS 1.1 still enabled
              │
              ▼
      Legacy connections possible
              │
              ▼
          Grade capped
              │
              ▼
               B
```

The principal issues are:

- TLS 1.0 enabled.
- TLS 1.1 enabled.
- Legacy CBC suites remain available.
- Some endpoints expose 3DES compatibility.
- Legacy clients can negotiate weaker configurations.

---

# Side-by-Side Comparison

| Security Control | MyChart | Amazon India |
|---|---|---|
| **SSL Labs grade** | **A+** | **B** |
| TLS 1.3 | ✅ | ✅ |
| TLS 1.2 | ✅ | ✅ |
| TLS 1.1 | ❌ | ⚠️ Enabled |
| TLS 1.0 | ❌ | ⚠️ Enabled |
| Forward Secrecy | ✅ | ✅ on modern suites |
| AES-GCM | ✅ | ✅ |
| ChaCha20-Poly1305 | Not primary in cited result | ✅ |
| Legacy CBC suites | Limited fallback | ⚠️ Multiple |
| 3DES | ❌ | ⚠️ Present on some tested endpoints |
| HSTS | ✅ | ✅ |
| Trusted certificate | ✅ | ✅ |
| Main weakness | Minor compatibility observations | Legacy protocol/cipher compatibility |

## Main Lesson

The difference between the two sites is not simply:

```text
"good encryption" vs "bad encryption"
```

Both support strong encryption.

The real difference is whether the server **also permits weaker alternatives**.

---

# Part 2 — MedDefense Portal Assessment

## Current Evidence

The MedDefense patient portal is hosted on:

```text
web-srv-01
10.10.2.50
TCP/443
```

The vulnerability scan found:

```text
TLS 1.0: ENABLED
TLS 1.2: ENABLED
TLS 1.3: NOT DOCUMENTED / NOT ENABLED
```

Finding 005 specifically associates the TLS 1.0 configuration with known weaknesses and recommends disabling TLS 1.0/1.1 and enabling TLS 1.3.

---

# Predicted SSL Labs Grade

## **Predicted: B at best**

If `portal.meddefense.local` were publicly accessible and all other TLS characteristics were acceptable, the most defensible prediction would be:

# **B**

The reason is that SSL Labs currently caps servers that support TLS 1.0 or TLS 1.1 at grade **B**.

However, because the complete cipher-suite configuration is not documented in the vulnerability scan, the actual grade could be **lower than B** if additional weak or insecure suites are enabled.

Therefore:

```text
Best-case prediction:       B

Possible actual result:     B or lower

A / A+ currently possible:  NO
```

---

# Issues Reducing the Portal's TLS Posture

| Issue | Evidence | Security Effect |
|---|---|---|
| **TLS 1.0 enabled** | Finding 005 | Grade capped; exposes legacy protocol behavior |
| **TLS 1.3 absent** | Finding 005 recommends enabling it | Loses modern TLS security/performance improvements |
| **HSTS missing** | Finding 012 | Browser may initially accept HTTP and be exposed to downgrade/SSL-stripping scenarios |
| **Certificate expires soon** | Finding 013 | Operational risk of browser certificate errors/outage |
| **No automated certificate renewal** | Finding 013 | Increases probability of accidental expiration |
| **Cipher suite baseline not documented** | Existing audit evidence | Weak CBC or legacy suites may remain enabled |
| **Default Apache configuration** | Existing audit evidence | Cryptographic policy is not explicitly enforced |
| **OCSP stapling not documented** | No evidence of configuration | Revocation checking could be improved |

MedDefense is therefore not suffering from just one TLS weakness. The portal currently lacks an explicit cryptographic baseline.

---

## Important Certificate Distinction

The certificate's **near-expiration state does not necessarily reduce the SSL Labs grade while the certificate is still valid**.

However, once it expires:

```text
Certificate expires
       │
       ▼
Browser trust fails
       │
       ▼
Security warning
       │
       ▼
Patients may be unable to use portal safely
```

Finding 013 specifically warns that browsers will present security warnings and that some patients may be unable to access the portal if renewal does not occur.

---

# MedDefense TLS Remediation Plan

| Priority | Action | Result |
|---|---|---|
| **Immediate** | Disable TLS 1.0 | Removes Finding 005 and SSL Labs B-grade cap |
| **Immediate** | Permit only TLS 1.2 and TLS 1.3 | Establishes modern protocol baseline |
| **Immediate** | Remove CBC, 3DES, RC4 and static-RSA cipher suites | Prevents negotiation of weak encryption |
| **Immediate** | Renew the patient portal certificate | Prevents upcoming certificate failure |
| **High** | Enable automated certificate renewal | Prevents recurrence of Finding 013 |
| **High** | Enable HSTS | Prevents browser downgrade to HTTP |
| **High** | Require ECDHE / forward secrecy | Protects historical sessions if server key is compromised |
| **High** | Disable TLS compression | Protects against compression-based attacks |
| **High** | Disable unsafe renegotiation | Prevents legacy renegotiation attacks |
| **High** | Review TLS session tickets | Protects forward secrecy |
| **Medium** | Enable OCSP stapling | Improves certificate-status delivery |
| **Medium** | Re-run TLS scanner after changes | Confirms remediation rather than assuming success |

---

# Part 3 — Hardened MedDefense TLS Configuration

## Platform Selected: Apache HTTP Server

The MedDefense portal already uses Apache, so the recommended configuration below is designed for:

```text
web-srv-01
Patient Portal
Apache HTTP Server
```

TLS 1.3 requires Apache to be linked against an OpenSSL version supporting TLS 1.3, such as OpenSSL 1.1.1 or newer. Apache's current `mod_ssl` documentation supports explicit TLS 1.3 protocol and cipher-suite configuration.

---

## Recommended Apache Configuration

```apache
# ================================================================
# MedDefense Patient Portal
# Hardened TLS Baseline
# ================================================================

<VirtualHost *:443>

    ServerName portal.meddefense.local

    SSLEngine On

    # ------------------------------------------------------------
    # Certificate
    # ------------------------------------------------------------

    SSLCertificateFile /etc/ssl/certs/portal-meddefense.crt
    SSLCertificateKeyFile /etc/ssl/private/portal-meddefense.key


    # ------------------------------------------------------------
    # Protocols
    # TLS 1.2 and TLS 1.3 only
    # ------------------------------------------------------------

    SSLProtocol -all +TLSv1.2 +TLSv1.3


    # ------------------------------------------------------------
    # TLS 1.3 Cipher Suites
    # ------------------------------------------------------------

    SSLCipherSuite TLSv1.3 \
        TLS_AES_256_GCM_SHA384:\
        TLS_CHACHA20_POLY1305_SHA256:\
        TLS_AES_128_GCM_SHA256


    # ------------------------------------------------------------
    # TLS 1.2 Cipher Suites
    # Forward secrecy + AEAD only
    # ------------------------------------------------------------

    SSLCipherSuite SSL \
        ECDHE-ECDSA-AES256-GCM-SHA384:\
        ECDHE-RSA-AES256-GCM-SHA384:\
        ECDHE-ECDSA-CHACHA20-POLY1305:\
        ECDHE-RSA-CHACHA20-POLY1305:\
        ECDHE-ECDSA-AES128-GCM-SHA256:\
        ECDHE-RSA-AES128-GCM-SHA256


    # ------------------------------------------------------------
    # Prefer server cipher ordering for TLS 1.2
    # ------------------------------------------------------------

    SSLHonorCipherOrder On


    # ------------------------------------------------------------
    # Preferred ephemeral curves
    # ------------------------------------------------------------

    SSLOpenSSLConfCmd Curves X25519:P-256:P-384


    # ------------------------------------------------------------
    # Disable TLS compression
    # ------------------------------------------------------------

    SSLCompression Off


    # ------------------------------------------------------------
    # Disable session tickets unless secure key rotation is managed
    # ------------------------------------------------------------

    SSLSessionTickets Off


    # ------------------------------------------------------------
    # Never permit insecure renegotiation
    # ------------------------------------------------------------

    SSLInsecureRenegotiation Off


    # ------------------------------------------------------------
    # OCSP Stapling
    # ------------------------------------------------------------

    SSLUseStapling On


    # ------------------------------------------------------------
    # HTTP Strict Transport Security
    # One year
    # ------------------------------------------------------------

    Header always set Strict-Transport-Security \
        "max-age=31536000; includeSubDomains"


    # ------------------------------------------------------------
    # Additional browser hardening
    # Addresses Finding 012
    # ------------------------------------------------------------

    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"


    # ------------------------------------------------------------
    # Application
    # ------------------------------------------------------------

    DocumentRoot /var/www/portal

</VirtualHost>


# ================================================================
# Global OCSP Stapling Cache
# Place in server-level Apache configuration.
# ================================================================

SSLStaplingCache shmcb:/var/run/apache2/ocsp_stapling(128000)
```

Apache documents `SSLProtocol` for restricting protocol versions and supports a dedicated `TLSv1.3` cipher-suite specification when linked against OpenSSL 1.1.1 or newer.

---

# Why Each Setting Was Chosen

| Configuration | Reason |
|---|---|
| `TLSv1.2` | Provides a secure compatibility baseline for clients that do not yet use TLS 1.3. |
| `TLSv1.3` | Provides the newest standardized TLS security model with simplified negotiation and modern AEAD-only cipher suites. |
| `TLS_AES_256_GCM_SHA384` | Provides AES-256 authenticated encryption with SHA-384 and is the first TLS 1.3 preference. |
| `TLS_CHACHA20_POLY1305_SHA256` | Provides strong authenticated encryption and excellent performance where AES hardware acceleration is unavailable. |
| `TLS_AES_128_GCM_SHA256` | Provides efficient 128-bit authenticated encryption and broad modern compatibility. |
| `ECDHE-*-AES256-GCM-SHA384` | Provides TLS 1.2 forward secrecy together with authenticated AES-256 encryption. |
| `ECDHE-*-CHACHA20-POLY1305` | Provides forward secrecy and modern authenticated encryption on devices where ChaCha20 is efficient. |
| `ECDHE-*-AES128-GCM-SHA256` | Provides a strong, widely supported TLS 1.2 fallback without reverting to legacy CBC. |
| `SSLHonorCipherOrder On` | Prevents TLS 1.2 clients from preferring an undesirable suite over MedDefense's approved ordering. |
| `X25519:P-256:P-384` | Restricts ephemeral key establishment to modern, strong elliptic-curve groups. |
| `SSLCompression Off` | Prevents compression-based TLS attacks such as CRIME. |
| `SSLSessionTickets Off` | Avoids weakening forward secrecy when session-ticket keys are not deliberately rotated and protected. |
| `SSLInsecureRenegotiation Off` | Prevents clients from using obsolete insecure renegotiation behavior. |
| `SSLUseStapling On` | Allows the server to provide certificate-revocation status during TLS establishment. |
| HSTS `max-age=31536000` | Forces browsers that have received the policy to use HTTPS for one year. |
| `includeSubDomains` | Extends the HSTS policy to subordinate names beneath the portal hostname. |

Apache specifically warns that TLS session tickets can compromise perfect forward secrecy when ticket keys are not rotated appropriately and provides `SSLSessionTickets Off` as the hardened alternative.

---

# Why These Cipher Suites?

The TLS 1.2 policy deliberately excludes:

```text
RC4
DES
3DES
AES-CBC
NULL encryption
anonymous DH
static RSA key exchange
```

and allows only:

```text
             ECDHE
                │
                ▼
        Forward Secrecy
                +
       ┌────────┴────────┐
       ▼                 ▼
    AES-GCM          ChaCha20
       │             Poly1305
       └────────┬────────┘
                ▼
       Authenticated Encryption
```

This means every permitted TLS 1.2 session provides both modern encryption and ephemeral key exchange.

Qualys considers cipher strength below 128 bits insecure and recommends TLS 1.2 as the minimum protocol together with TLS 1.3 where supported.

---

# HSTS Recommendation

Finding 012 currently shows:

```text
Strict-Transport-Security: MISSING
```



The proposed configuration adds:

```apache
Header always set Strict-Transport-Security \
    "max-age=31536000; includeSubDomains"
```

This means:

```text
31536000 seconds
      │
      ▼
     1 year
```

After the browser receives the header, it remembers that the portal must be contacted over HTTPS.

I would **not initially add `preload`** until MedDefense has deliberately confirmed that every relevant hostname is permanently HTTPS-capable, because HSTS preloading is intentionally difficult to reverse.

---

# Certificate Renewal

The hardened TLS configuration must be accompanied by certificate lifecycle automation.

The current state is:

```text
Certificate issuer:      Let's Encrypt
Certificate expiry:      23 days
Automatic renewal:       NOT CONFIGURED
```



The target state should be:

```text
Certificate
     │
     ▼
Automatic Renewal
     │
     ▼
Automatic Deployment
     │
     ▼
Apache Reload
     │
     ▼
Validation
     │
     ▼
Expiration Monitoring
```

Certificate renewal should therefore be treated as part of TLS security rather than a separate administrative task.

---

# Post-Change Validation

After editing the Apache configuration, validate it before restarting:

```bash
sudo apachectl configtest
```

Expected:

```text
Syntax OK
```

Reload Apache:

```bash
sudo systemctl reload apache2
```

Then confirm that TLS 1.0 fails:

```bash
openssl s_client \
    -connect portal.meddefense.local:443 \
    -servername portal.meddefense.local \
    -tls1
```

Expected result:

```text
Handshake failure
```

Confirm TLS 1.2 succeeds:

```bash
openssl s_client \
    -connect portal.meddefense.local:443 \
    -servername portal.meddefense.local \
    -tls1_2
```

Confirm TLS 1.3 succeeds:

```bash
openssl s_client \
    -connect portal.meddefense.local:443 \
    -servername portal.meddefense.local \
    -tls1_3
```

The final requirement should be:

```text
TLS 1.0    ❌
TLS 1.1    ❌
TLS 1.2    ✅
TLS 1.3    ✅
```

---

# Part 4 — The Downgrade Attack

A TLS downgrade attack occurs when an active attacker interferes with protocol negotiation or fallback behavior so that two systems that could use a strong TLS version instead establish a connection using an older, weaker version. Because MedDefense currently accepts both TLS 1.0 and TLS 1.2, a vulnerable legacy client or intermediary that permits fallback could potentially be driven toward TLS 1.0, exposing the session to weaknesses associated with the older protocol and its cipher ecosystem. Modern TLS implementations contain downgrade defenses, but continuing to offer obsolete protocols unnecessarily preserves an attack surface. The simplest and strongest prevention is to **disable TLS 1.0 and TLS 1.1 completely and permit only TLS 1.2 and TLS 1.3**.

---

# Final Assessment

The SSL Labs comparison demonstrates that simply supporting TLS 1.3 does not guarantee a strong overall configuration. `www.amazon.in` supports modern TLS, strong forward-secret key exchange, and modern AEAD suites, but continued TLS 1.0/1.1 compatibility caps its SSL Labs grade at **B**. In comparison, `www.mychart.org` permits only TLS 1.2 and TLS 1.3, deploys long-duration HSTS, uses modern forward-secret cipher suites, and receives **A+**.

MedDefense currently resembles the weaker model because TLS 1.0 remains enabled. Finding 005 therefore represents more than a theoretical problem: under current SSL Labs methodology, legacy TLS support alone prevents the portal from obtaining an A-grade result. 

The remediation target is clear:

```text
REMOVE TLS 1.0
      +
ENABLE TLS 1.3
      +
KEEP TLS 1.2
      +
ALLOW AEAD CIPHERS ONLY
      +
REQUIRE FORWARD SECRECY
      +
ENABLE HSTS
      +
AUTOMATE CERTIFICATE RENEWAL
      =
HARDENED MEDDEFENSE PATIENT PORTAL
```

Once the changes are deployed, MedDefense should repeat protocol and cipher testing internally and validate that TLS 1.0/1.1 handshakes fail before closing Findings 005, 012, and 013.
