# Task 8 — The Certificate Anatomy

## Goal

Inspect real X.509 TLS certificates, identify the certificate fields that matter for security, diagnose an intentionally broken certificate, and define an appropriate certificate profile for the MedDefense patient portal.

---

# Why Certificate Anatomy Matters

When a patient connects to a secure website, the browser performs several checks before trusting the connection:

```text
                  HTTPS CONNECTION
                         │
                         ▼
                Server Certificate
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
       Identity       Validity       Trust Chain
          │              │              │
      Does SAN       Is today       Was it signed
      match site?    within dates?  by a trusted CA?
          │              │              │
          └──────────────┼──────────────┘
                         ▼
                  Public Key Check
                         │
                         ▼
                  Usage / Purpose
                         │
                         ▼
                 Certificate Trusted?
```

A valid certificate therefore provides much more than encryption. It allows the browser to determine whether the server presenting the certificate is the server the user intended to contact.

This is particularly important for MedDefense because the current patient portal certificate is approaching expiration and does not have automated renewal configured.

---

# Part 1 — Inspect Three Real Certificates

Three certificates were downloaded and inspected:

| Website | Certificate Category | Purpose of Test |
|---|---|---|
| `letsencrypt.org` | Let's Encrypt public certificate | Inspect a certificate issued by a widely used automated CA |
| `github.com` | Commercial CA certificate | Inspect a certificate issued by Sectigo |
| `self-signed.badssl.com` | Intentionally broken certificate | Demonstrate failure of certificate trust |

---

## 1. Download the Certificates

### Let's Encrypt

```bash id="6ccyhg"
openssl s_client -connect letsencrypt.org:443 \
    -servername letsencrypt.org \
    -showcerts </dev/null 2>/dev/null \
    | openssl x509 -outform PEM > letsencrypt.pem
```

### GitHub

```bash id="lslh01"
openssl s_client -connect github.com:443 \
    -servername github.com \
    -showcerts </dev/null 2>/dev/null \
    | openssl x509 -outform PEM > github.pem
```

### BadSSL — Self-Signed Certificate

```bash id="8cyvv8"
openssl s_client -connect self-signed.badssl.com:443 \
    -servername self-signed.badssl.com \
    -showcerts </dev/null 2>/dev/null \
    | openssl x509 -outform PEM > badssl.pem
```

---

# 2. Inspect the Certificates

The certificates were converted to readable text with:

```bash id="qcjlid"
openssl x509 -in letsencrypt.pem -text -noout > letsencrypt.txt
openssl x509 -in github.pem -text -noout > github.txt
openssl x509 -in badssl.pem -text -noout > badssl.txt
```

---

# Certificate Comparison

## Comparative X.509 Reference Table

| Field | Let's Encrypt | GitHub | Self-Signed BadSSL |
|---|---|---|---|
| **Subject** | `CN=letsencrypt.org` | `CN=github.com` | `C=US, ST=California, L=San Francisco, O=BadSSL, CN=*.badssl.com` |
| **Organization (O)** | Not present | Not present | `BadSSL` |
| **Locality (L)** | Not present | Not present | `San Francisco` |
| **State (ST)** | Not present | Not present | `California` |
| **Country (C)** | Not present | Not present | `US` |
| **Issuer** | `C=US, O=Let's Encrypt, CN=YE2` | `C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36` | Same as Subject — self-signed |
| **Not Before** | Sep 4, 2026 | Sep 1, 2026 | Sep 29, 2026 |
| **Not After** | Dec 3, 2026 | Nov 29, 2026 | Sep 28, 2028 |
| **Serial Number** | `05:43:93:3b:e3:86:b3:a2:b3:ad:d5:34:f2:10:3b:c8:b6:5f` | `a5:9e:bd:b5:96:75:1d:b7:f5:c0:95:07:96:13:95:3c` | `fb:13:b2:fe:b3:e1:ad:13` |
| **Certificate Signature Algorithm** | `ecdsa-with-SHA384` | `ecdsa-with-SHA256` | `sha256WithRSAEncryption` |
| **Public Key Algorithm** | Elliptic Curve | Elliptic Curve | RSA |
| **Public Key Size** | P-256 / 256-bit | P-256 / 256-bit | RSA-2048 |
| **Key Usage** | Digital Signature | Digital Signature | Not present in captured certificate |
| **Extended Key Usage** | TLS Web Server Authentication | TLS Web Server Authentication | Not present in captured certificate |
| **SAN** | Multiple Let's Encrypt domains including `letsencrypt.org` and `www.letsencrypt.org` | `github.com`, `www.github.com` | `*.badssl.com`, `badssl.com` |
| **OCSP URL** | Not shown in captured AIA | `http://ocsp.sectigo.com` | Not present |
| **CA Issuer URL** | `http://ye2.i.lencr.org/` | Sectigo CA certificate URL | Not present |
| **CA Certificate?** | No — `CA:FALSE` | No — `CA:FALSE` | No — `CA:FALSE` |
| **Trust Result** | Trusted public certificate | Trusted public certificate | **Untrusted/self-signed** |

The Let's Encrypt certificate uses an EC P-256 public key, is signed using ECDSA with SHA-384, and contains the required server-authentication extensions and SAN entries. 

The GitHub certificate is issued by Sectigo, uses an EC P-256 key, includes Digital Signature and TLS Web Server Authentication usages, and provides both OCSP and CA Issuer information.  Its SAN extension explicitly covers both `github.com` and `www.github.com`.

The BadSSL certificate differs fundamentally because its Subject and Issuer identify BadSSL itself rather than an independent trusted CA.

---

# What Each Certificate Field Means

| X.509 Field | Security Meaning |
|---|---|
| **Subject** | Identifies the entity the certificate represents |
| **Issuer** | Identifies the CA that signed the certificate |
| **Validity — Not Before / Not After** | Defines when the certificate may be trusted |
| **Serial Number** | Unique identifier assigned to the certificate by the issuing CA |
| **Signature Algorithm** | Algorithm used by the issuer to digitally sign the certificate |
| **Public Key Algorithm** | Cryptographic key belonging to the certificate holder |
| **SAN** | Lists the DNS names or IP addresses the certificate is valid for |
| **Key Usage** | Defines permitted cryptographic operations |
| **Extended Key Usage** | Defines higher-level purposes such as TLS server authentication |
| **Authority Information Access** | Provides locations for CA certificates and often OCSP status checking |
| **Basic Constraints** | Indicates whether the certificate may act as a CA |

---

# Certificate 1 — Let's Encrypt

## Identity

```text id="mpgcyy"
Subject:
    CN = letsencrypt.org

Issuer:
    C  = US
    O  = Let's Encrypt
    CN = YE2
```

The certificate identifies `letsencrypt.org`, while a separate Let's Encrypt CA issued and signed it.

---

## Validity

```text id="e9ert5"
Not Before: Sep  4 14:34:32 2026 GMT
Not After : Dec  3 14:34:31 2026 GMT
```

This is approximately a **90-day certificate**.

---

## Cryptography

```text id="gtzamn"
Signature Algorithm:
    ecdsa-with-SHA384

Public Key Algorithm:
    id-ecPublicKey

Public-Key:
    256 bit

Curve:
    prime256v1 / NIST P-256
```

P-256 provides approximately 128-bit classical security while using a significantly smaller key than equivalent RSA configurations.

---

## Key Usage

```text id="6qktjh"
Key Usage:
    Digital Signature

Extended Key Usage:
    TLS Web Server Authentication
```

This makes the certificate suitable for authenticating a TLS web server.

---

## Subject Alternative Names

Examples include:

```text id="3r2vfz"
DNS:letsencrypt.org
DNS:www.letsencrypt.org
DNS:letsencrypt.com
DNS:www.letsencrypt.com
DNS:lencr.org
DNS:www.lencr.org
```

Modern browsers primarily use the **SAN extension**, rather than the Common Name alone, when determining whether a certificate matches a requested hostname.

---

## Authority Information Access

```text id="bg4zyb"
CA Issuers:
    http://ye2.i.lencr.org/
```

The captured certificate does not show an OCSP responder URL in its Authority Information Access section.

---

# Certificate 2 — GitHub

## Identity

```text id="3moqbc"
Subject:
    CN = github.com

Issuer:
    C  = GB
    O  = Sectigo Limited
    CN = Sectigo Public Server Authentication CA DV E36
```

Unlike the BadSSL example, GitHub's certificate is signed by a publicly trusted external Certification Authority.

---

## Validity

```text id="lmq1gp"
Not Before: Sep  1 00:00:00 2026 GMT
Not After : Nov 29 23:59:59 2026 GMT
```

The certificate is valid for approximately **90 days**.

---

## Cryptography

```text id="zjj9f3"
Signature Algorithm:
    ecdsa-with-SHA256

Public Key Algorithm:
    id-ecPublicKey

Public-Key:
    256 bit

Curve:
    prime256v1 / NIST P-256
```

Both GitHub and Let's Encrypt therefore demonstrate the use of modern ECC P-256 server keys.

---

## Key Usage

```text id="28pq4l"
Key Usage:
    Digital Signature

Extended Key Usage:
    TLS Web Server Authentication
```

---

## Subject Alternative Names

```text id="aj17mv"
DNS:github.com
DNS:www.github.com
```

This means the same certificate can authenticate both listed hostnames.

---

## Authority Information Access

```text id="pz4od4"
CA Issuers:
    http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt

OCSP:
    http://ocsp.sectigo.com
```

The CA Issuer location helps clients obtain the issuing certificate when constructing the certificate chain.

The OCSP location can be used to obtain information about whether a certificate has been revoked.

---

# Certificate 3 — Self-Signed BadSSL

## Identity

```text id="4dqg1v"
Subject:
    C  = US
    ST = California
    L  = San Francisco
    O  = BadSSL
    CN = *.badssl.com
```

Issuer:

```text id="wve2cw"
C  = US
ST = California
L  = San Francisco
O  = BadSSL
CN = *.badssl.com
```

The Subject and Issuer are the same.

That is the key clue that this certificate is **self-signed**.

---

## Validity

```text id="wb1u7a"
Not Before: Sep 29 21:01:43 2026 GMT
Not After : Sep 28 21:01:43 2028 GMT
```

The certificate is currently within its validity period.

Therefore, expiration is **not** what makes this certificate invalid.

---

## Cryptography

```text id="ilxs54"
Signature Algorithm:
    sha256WithRSAEncryption

Public Key Algorithm:
    rsaEncryption

Public-Key:
    2048 bit
```

RSA-2048 and SHA-256 are not themselves the problem.

This illustrates an important PKI principle:

> A certificate may use acceptable cryptographic algorithms and still be untrustworthy.

---

## Subject Alternative Names

```text id="x8w1hc"
DNS:*.badssl.com
DNS:badssl.com
```

The wildcard covers:

```text id="u1spxu"
self-signed.badssl.com
```

so the hostname is also not the main problem.

The captured certificate contains only Basic Constraints and SAN among the major extensions shown; Key Usage, Extended Key Usage, and Authority Information Access are not present in the supplied output.

---

# Part 2 — The Broken Certificate

## What Is Wrong?

The certificate presented by:

```text id="etkx85"
self-signed.badssl.com
```

is **self-signed**.

A normal publicly trusted server certificate follows a chain similar to:

```text id="m2dfg6"
Website Certificate
        │
        ▼
Intermediate CA
        │
        ▼
Trusted Root CA
        │
        ▼
Browser Trust Store
        │
        ▼
      TRUST
```

The BadSSL certificate instead effectively has:

```text id="g9exd8"
Website Certificate
        │
        └──── signs itself
                  │
                  ▼
             No trusted CA
                  │
                  ▼
             UNTRUSTED
```

The certificate contains:

```text id="tlnkh3"
Subject = BadSSL / *.badssl.com
Issuer  = BadSSL / *.badssl.com
```

rather than being signed by a CA already trusted by the browser.

---

## What Would the Browser Display?

A modern browser would display a prominent certificate/privacy warning.

Typical wording includes:

```text id="8ovylq"
Your connection is not private
```

or an error equivalent to:

```text id="om72c6"
Certificate authority invalid
```

The precise wording and error code depend on the browser and operating system.

---

# Why Is This Dangerous?

TLS encryption alone is not sufficient.

The browser must also authenticate the server.

With a self-signed certificate that the browser has no independent reason to trust, there is no trusted third party establishing:

```text id="i32b12"
"This public key genuinely belongs
to the website you intended to visit."
```

An attacker performing a man-in-the-middle attack could generate another self-signed certificate and claim an identity of their choosing.

Without a trusted authentication mechanism, the user cannot reliably distinguish the legitimate server from an impersonator.

---

# Should a MedDefense Patient Proceed?

**No.**

If the MedDefense patient portal displayed this type of certificate warning, patients should not bypass the warning and continue entering credentials or health information.

A certificate warning on a healthcare portal means that the browser cannot establish the expected server identity. Proceeding could expose:

```text id="h7u5ax"
Login credentials
Protected Health Information
Messages to clinicians
Appointment information
Billing information
```

to an impersonated or intercepted connection.

The appropriate response would be to stop the session and report the certificate problem through a known MedDefense support channel.

---

# Part 3 — Ideal MedDefense Patient Portal Certificate

## Recommended Certificate Profile

| Property | MedDefense Recommendation |
|---|---|
| **Certificate type** | **OV — Organization Validation** |
| **Issuer** | Publicly trusted OV-capable CA with automated renewal support |
| **Public key** | **ECDSA P-256** |
| **Signature/hash** | SHA-256 or stronger |
| **SAN** | Exact public patient-portal hostname and only additional hostnames genuinely required |
| **Extended Key Usage** | TLS Web Server Authentication |
| **Key Usage** | Digital Signature |
| **Validity** | **Approximately 90 days**, automatically renewed |
| **Wildcard?** | **No — prefer a specific portal certificate** |
| **Renewal** | Fully automated with monitoring and alerting |
| **Private key** | Protected, non-exported where practical, and restricted to the portal service |

---

# 1. Certificate Type — OV

I would select an **Organization Validation (OV)** certificate for the MedDefense patient portal.

### DV — Domain Validation

A DV certificate establishes primarily that the applicant controls the domain.

It is cryptographically valid and can provide exactly the same TLS encryption strength as OV or EV.

### OV — Organization Validation

OV additionally validates organizational identity information before issuance.

For MedDefense, this provides a useful identity-assurance layer for a healthcare organization handling sensitive patient information.

### EV — Extended Validation

EV requires additional organizational verification, but modern browsers generally no longer provide the prominent visual distinction that historically made EV attractive.

For MedDefense, **OV provides a reasonable balance between organizational identity validation and operational complexity**.

Importantly:

> OV is not cryptographically stronger than DV. The recommendation concerns organizational identity validation, not stronger AES or TLS encryption.

---

# 2. Certificate Authority

MedDefense should use a **publicly trusted CA that supports OV certificates and automated lifecycle management**, such as an established commercial public CA.

The critical requirements are not the CA brand alone. MedDefense should require:

```text id="6z7yfg"
✓ Browser/root-store trust
✓ Organization validation
✓ Automated issuance and renewal
✓ Revocation support
✓ Certificate Transparency support
✓ ACME or equivalent automation
✓ Administrative access controls
✓ Renewal monitoring and alerting
```

This is directly relevant to the existing MedDefense problem because the current portal certificate is close to expiration and **automatic renewal is not configured**.

Certificate automation should therefore be treated as a security requirement rather than an optional convenience.

---

# 3. Subject Alternative Names

The SAN extension should include the **exact public DNS hostname patients use to access the portal**.

Conceptually:

```text id="7qfhez"
DNS:portal.<MedDefense-public-domain>
```

Additional SANs should be included only when they represent legitimate production access paths.

For example, if both of these were genuinely required:

```text id="quw1zz"
DNS:portal.<MedDefense-public-domain>
DNS:www.portal.<MedDefense-public-domain>
```

both could appear in SAN.

MedDefense should avoid adding unnecessary names because every additional hostname increases the scope of the certificate.

The current project evidence refers to `portal.meddefense.local`. For a real publicly trusted Internet-facing certificate, MedDefense should use a valid public DNS name rather than an internal `.local` hostname; CA/Browser Forum requirements prohibit publicly trusted CAs from issuing certificates for internal names.

---

# 4. Key Algorithm and Size

## Recommended

```text id="ephslj"
ECDSA
NIST P-256
256-bit EC key
```

This is the same basic public-key configuration observed on both:

```text id="c99e5f"
letsencrypt.org
github.com
```

in the laboratory.

P-256 provides approximately **128-bit classical security** while using significantly smaller keys and less computation than comparably strong RSA configurations.

For environments requiring compatibility with older clients, MedDefense could also maintain RSA compatibility, but a modern portal should prefer ECC where client support has been validated.

---

# 5. Validity Period

## Recommended

**90 days with automated renewal.**

This balances short credential lifetime with manageable operations.

The Let's Encrypt certificate observed in the exercise follows approximately this model, running from September 4 to December 3, 2026.

As of October 2026, the CA/Browser Forum permits publicly trusted subscriber TLS certificates issued between March 15, 2026 and March 15, 2027 to have a maximum validity of **200 days**.

A 90-day MedDefense certificate therefore fits comfortably within the current limit and encourages automated certificate lifecycle management. Let's Encrypt likewise continues to use 90 days as its normal default lifetime.

The critical design requirement is:

```text id="4j6pq1"
DO NOT depend on manual renewal.
```

Instead:

```text id="t1gk0u"
Issue
  │
  ▼
Deploy
  │
  ▼
Monitor
  │
  ▼
Automatically Renew
  │
  ▼
Validate Deployment
  │
  ▼
Repeat
```

---

# 6. Wildcard vs. Single-Domain

## Recommended: Single-Domain / Limited SAN Certificate

MedDefense should **not use a wildcard certificate for the patient portal unless there is a strong operational requirement**.

A wildcard such as:

```text id="s6lfn9"
*.meddefense.example
```

could potentially protect:

```text id="cb69dg"
portal.meddefense.example
billing.meddefense.example
vpn.meddefense.example
ehr.meddefense.example
```

with the same private key.

That increases the impact of key compromise.

A portal-specific certificate limits the scope:

```text id="gjylvc"
Patient Portal Certificate
        │
        ▼
portal.<public-domain>
        │
        ▼
Compromise affects
primarily this service
```

rather than:

```text id="mjzo7e"
Wildcard Certificate
        │
        ├── Patient Portal
        ├── Billing
        ├── VPN
        ├── EHR
        └── Other systems
```

For a sensitive healthcare environment, limiting cryptographic trust boundaries is preferable.

---

# Final MedDefense Certificate Profile

```text id="z3lo4s"
┌─────────────────────────────────────────────────────┐
│         MEDDEFENSE PATIENT PORTAL CERTIFICATE       │
├─────────────────────────────────────────────────────┤
│ Type:            Organization Validation (OV)       │
│                                                     │
│ Issuer:          Trusted public OV-capable CA       │
│                                                     │
│ Public Key:      ECDSA P-256                        │
│                                                     │
│ Signature:       SHA-256 or stronger                │
│                                                     │
│ SAN:             Exact patient portal FQDN          │
│                                                     │
│ Key Usage:       Digital Signature                  │
│                                                     │
│ Extended Usage:  TLS Web Server Authentication      │
│                                                     │
│ Validity:        ~90 days                           │
│                                                     │
│ Renewal:         Fully automated                    │
│                                                     │
│ Certificate:     Portal-specific, not wildcard      │
│                                                     │
│ Private Key:     Restricted and securely stored     │
└─────────────────────────────────────────────────────┘
```

---

# Conclusion

The three certificate inspections demonstrate that certificate security depends on several controls working together.

Both the Let's Encrypt and GitHub certificates have valid identities, current validity periods, appropriate SAN entries, modern ECC public keys, suitable server-authentication purposes, and certificate chains anchored in publicly trusted Certification Authorities. 

The BadSSL certificate demonstrates the opposite case. Its RSA-2048 key and SHA-256 signature are not inherently weak, its hostname is covered by its wildcard SAN, and its dates are valid. The failure is **trust**: the certificate signs itself rather than chaining to an authority trusted by the browser.

The central lesson is:

```text id="0dpw4j"
Encryption alone is not enough.

A secure TLS certificate must provide:

      VALID IDENTITY
           +
      VALID TIME PERIOD
           +
      TRUSTED ISSUER
           +
      CORRECT HOSTNAME
           +
      STRONG KEY
           +
      CORRECT KEY USAGE
           =
      TRUSTED TLS CONNECTION
```

For MedDefense, the most urgent operational lesson is certificate lifecycle management. A strong certificate still becomes unusable when it expires. Because the current portal certificate is nearing expiration without automated renewal, the replacement certificate should be deployed together with **automated renewal, monitoring, and expiration alerting**, not merely replaced once and forgotten.
