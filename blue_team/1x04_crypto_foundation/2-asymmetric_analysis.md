# Task 2 — The Asymmetric Engine

## Goal

Generate RSA and ECC key pairs, experimentally demonstrate the size limitation of asymmetric encryption, compare RSA and ECC key sizes, and explain why modern cryptographic systems combine asymmetric and symmetric cryptography.

---

# Part 1 — RSA Key Generation and Encryption

## Generate RSA-2048 Key Pair

Generate a 2048-bit RSA private key:

```bash
openssl genrsa -out rsa_private.pem 2048
```

Extract the corresponding RSA public key:

```bash
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
```

Verify the keys:

```bash
ls -lh rsa_*.pem
openssl rsa -in rsa_private.pem -text -noout | head -20
```

Observed output:

```text
-rw------- 1 kali kali 1.7K Oct  1 13:37 rsa_private.pem
-rw-rw-r-- 1 kali kali  451 Oct  1 13:37 rsa_public.pem

Private-Key: (2048 bit, 2 primes)
modulus:
    00:c8:e4:f8:08:ba:12:16:e8:ac:99:32:b6:9f:53:
    ce:c9:9b:f3:d0:06:ee:9f:43:78:4c:7e:e1:35:32:
    68:87:9b:48:d3:75:a7:d4:4a:6d:27:49:c5:11:23:
    ...
```

The output confirms that OpenSSL successfully generated a **2048-bit RSA private key** and its corresponding public key. The private key must remain confidential, while the public key can be distributed to other systems that need to encrypt information for the owner or verify signatures.

---

## Encrypt and Decrypt with RSA

Create a small MedDefense patient record:

```bash
echo -n "Patient: Jane Doe | DOB: 1985-03-14 | MRN: MED-50421 | Diagnosis: Atrial Fibrillation" > patient_record.txt
```

Encrypt the patient record using the RSA public key:

```bash
openssl pkeyutl -encrypt \
    -pubin \
    -inkey rsa_public.pem \
    -in patient_record.txt \
    -out patient_record_rsa.enc
```

Decrypt the ciphertext using the RSA private key:

```bash
openssl pkeyutl -decrypt \
    -inkey rsa_private.pem \
    -in patient_record_rsa.enc \
    -out patient_record_rsa.dec
```

Verify that the decrypted file is identical to the original:

```bash
diff patient_record.txt patient_record_rsa.dec && echo "RSA: Files match"
```

Observed output:

```text
RSA: Files match
```

The successful comparison demonstrates the basic asymmetric model. Data encrypted with the public RSA key can be recovered using the corresponding private key.

---

## Attempt to Encrypt a 100 MB File with RSA

Attempting to encrypt the large test file directly:

```bash
openssl pkeyutl -encrypt \
    -pubin \
    -inkey rsa_public.pem \
    -in testfile \
    -out testfile_rsa.enc 2>&1
```

Produced:

```text
Public Key operation error
20CD93A4FFFF0000:error:0200006E:rsa routines:ossl_rsa_padding_add_PKCS1_type_2_ex:data too large for key size:../crypto/rsa/rsa_pk1.c:132:
```

## Why RSA Cannot Encrypt Large Files

RSA can operate only on plaintext small enough to fit inside the RSA modulus after the required cryptographic padding is added. With a 2048-bit RSA key and PKCS#1 v1.5 encryption padding, a single operation can encrypt only about **245 bytes**, so a 100 MB file is far too large.

In real systems, RSA is therefore used for small values such as cryptographic keys rather than for bulk files. A symmetric cipher such as AES encrypts the actual file, while RSA or another asymmetric mechanism helps protect or establish the symmetric key.

---

# Part 2 — ECC Key Generation

## Generate ECC Key Pair — P-256

Generate a private key using the NIST P-256 elliptic curve:

```bash
openssl ecparam -genkey -name prime256v1 -out ecc_private.pem
```

Generate the corresponding public key:

```bash
openssl ec -in ecc_private.pem -pubout -out ecc_public.pem
```

Verify the keys:

```bash
ls -lh ecc_*.pem
openssl ec -in ecc_private.pem -text -noout | head -15
```

Observed output:

```text
-rw------- 1 kali kali 302 Oct  1 13:50 ecc_private.pem
-rw-rw-r-- 1 kali kali 178 Oct  1 13:50 ecc_public.pem

Private-Key: (256 bit)
priv:
    7c:5e:6f:36:cd:bd:92:12:07:be:83:d5:c1:b0:22:
    05:4c:b3:1b:1a:ae:dd:1a:b3:ef:4b:15:5e:ae:28:
    dd:0c
pub:
    04:6c:d5:f8:ca:3a:f8:85:75:f4:66:7e:8b:23:cd:
    ...
ASN1 OID: prime256v1
NIST CURVE: P-256
```

The output confirms successful generation of an ECC key pair using the **NIST P-256 curve**.

---

## Compare RSA vs. ECC Key Sizes

The generated private-key files have the following approximate sizes:

| Key | Cryptographic Size | PEM File Size | Approximate Security Strength |
|---|---:|---:|---:|
| RSA private key | 2048 bits | 1.7 KB | 112 bits |
| ECC P-256 private key | 256-bit curve | 302 bytes | 128 bits |

Using the displayed file sizes:

**1,700 ÷ 302 ≈ 5.6**

Therefore, the RSA private-key file is approximately **5.6 times larger** than the ECC private-key file.

ECC achieves stronger security per key bit because attacking properly implemented elliptic-curve cryptography requires solving the elliptic-curve discrete logarithm problem, while RSA security depends on the difficulty of factoring large integers. NIST-equivalent security estimates place RSA-2048 at approximately **112-bit security**, P-256 at approximately **128-bit security**, and P-384 at approximately **192-bit security**.

This efficiency is particularly relevant to MedDefense's constrained medical-device environment. BD Alaris pumps and Philips IntelliVue monitors have more limited processing, memory, and network resources than conventional servers, so smaller ECC keys can reduce computational and communication overhead while maintaining strong cryptographic security.

---

# Part 3 — The Hybrid Model

Modern secure communications use a **hybrid cryptographic model** because symmetric and asymmetric cryptography solve different problems. Asymmetric cryptography is used during a handshake to authenticate parties and establish shared secret keying material without requiring both parties to possess the same secret beforehand. Once session keys have been established, a fast symmetric cipher such as AES-GCM encrypts the actual application data because symmetric cryptography is much more efficient for large volumes of information. This provides the key-distribution and authentication benefits of asymmetric cryptography together with the speed and scalability of symmetric encryption. As a result, the combination is superior to using asymmetric encryption for all data or trying to distribute symmetric keys manually.

For the **MedDefense patient portal**, the TLS handshake is responsible for the asymmetric authentication and key-establishment portion of the connection, while the negotiated symmetric cipher protects the bulk HTTPS application traffic after the handshake. The MedDefense audit currently confirms support for **TLS 1.0 and TLS 1.2**, with TLS 1.3 unavailable, but the exact cipher suites and key-exchange algorithms are not documented; therefore, the precise asymmetric algorithm currently negotiated by the portal cannot be established from the available evidence.

---

# Part 4 — Cryptographic Algorithm and Key Length Comparison

## Healthcare Interpretation

HIPAA does not publish a simple whitelist of individual encryption algorithms. HHS guidance instead points organizations protecting electronic PHI toward encryption processes consistent with appropriate NIST standards and FIPS-validated cryptographic implementations.

For the table below:

**Approved** means suitable for new MedDefense protection of regulated healthcare data when used in an appropriate modern protocol, mode, and validated implementation.

**Conditional** means cryptographically strong but not the default choice for a MedDefense environment requiring strict NIST/FIPS alignment.

**Not Approved** means the algorithm should not be used to provide new protection for MedDefense regulated data.

## Unified Comparative Reference Table

| Algorithm | Type | Key Length | Approx. Equivalent Security | Primary Purpose | Healthcare / Regulated-Data Status | Current Security Status | MedDefense Usage |
|---|---|---:|---:|---|---|---|---|
| **AES-128** | Symmetric block cipher | 128 bits | **128 bits** | Bulk encryption of files, databases, disks, VPN and TLS traffic | **Approved** | Strong. NIST lists AES-128 encryption/decryption as acceptable. | No specific AES-128 deployment documented. |
| **AES-192** | Symmetric block cipher | 192 bits | **192 bits** | Bulk encryption where a higher security margin than AES-128 is desired | **Approved** | Strong. NIST lists AES-192 as acceptable. | No specific AES-192 deployment documented. |
| **AES-256** | Symmetric block cipher | 256 bits | **256 bits** | High-strength bulk encryption for storage, backups, VPNs and application data | **Approved / Recommended** | Strong. NIST lists AES-256 as acceptable. | **In use:** MedDefense's IPSec site-to-site tunnels use AES-256. NAS-01 also supports AES-256-CBC shared-folder encryption, although this protection is currently disabled.  |
| **RSA-2048** | Asymmetric | 2048-bit modulus | **≈112 bits** | Digital signatures, authentication, and key establishment; not bulk encryption | **Approved for current use, but not preferred for long-lived new deployments** | Currently acceptable in approved schemes, but its ≈112-bit strength provides less long-term margin than modern 128-bit-strength options. | No RSA implementation is specifically confirmed by the MedDefense audit. The patient portal uses a certificate, but its public-key algorithm is not documented. |
| **RSA-4096** | Asymmetric | 4096-bit modulus | **≈150 bits** | Digital signatures, authentication, and key establishment | **Approved** | Stronger than RSA-2048 but substantially larger and computationally heavier. | No current MedDefense RSA-4096 use documented. |
| **ECC P-256** | Asymmetric elliptic curve | 256-bit curve | **≈128 bits** | ECDH/ECDHE key agreement and ECDSA digital signatures | **Approved / Recommended** | Strong. Provides about 128-bit security with much smaller keys than RSA. | No existing deployment confirmed. Appropriate candidate for MedDefense TLS and resource-constrained medical devices. |
| **ECC P-384** | Asymmetric elliptic curve | 384-bit curve | **≈192 bits** | Higher-strength ECDH/ECDHE and ECDSA operations | **Approved / Recommended** | Strong. Provides approximately 192-bit security. | No current MedDefense deployment documented. Suitable where a higher security margin is required. |
| **DES** | Symmetric block cipher | 56 effective bits | **≈56 bits** | Historical bulk encryption | **Not Approved** | **Obsolete/broken for modern protection.** DES provides far too little security for regulated healthcare information. | **Legacy exposure exists:** MedDefense Active Directory still permits DES Kerberos encryption and Finding 018 requires its removal. |
| **3DES / TDEA** | Symmetric block cipher | 168 nominal bits using three keys | **≈112 bits** | Legacy replacement for DES | **Not Approved for new protection** | NIST disallowed three-key TDEA for applying new cryptographic protection after December 31, 2023. Legacy decryption of already-protected information may continue. | No current MedDefense 3DES deployment documented. It must not be introduced into the new cryptographic baseline. |
| **ChaCha20-Poly1305** | Symmetric stream cipher + authenticator (AEAD) | 256-bit key; 128-bit authentication tag | **256-bit key strength; 128-bit authentication tag** | Authenticated bulk encryption, especially in TLS and software environments without fast AES hardware | **Conditional** | Modern and strong. RFC 8439 specifies a 256-bit ChaCha20 key, 96-bit nonce and Poly1305 authentication. It is widely used, but it is not the default NIST/FIPS algorithm choice for a strict MedDefense compliance baseline. | No current MedDefense use documented. AES-GCM should remain the default where NIST/FIPS alignment is required. |
| **RC4** | Symmetric stream cipher | Historically variable; commonly 128 bits | **No acceptable modern security strength** | Historical stream encryption | **Not Approved** | **Obsolete/insecure.** RFC 7465 requires TLS implementations never to negotiate RC4 because of exploitable keystream weaknesses. | **Legacy exposure exists:** MedDefense Active Directory still permits RC4 Kerberos tickets, creating Kerberoasting exposure identified in Finding 018. |

## Quick Comparative Summary

| Requirement | Preferred Choice | Reason |
|---|---|---|
| **Bulk data encryption** | **AES-256-GCM** | Fast symmetric encryption with confidentiality and authentication |
| **General modern symmetric alternative** | **ChaCha20-Poly1305** | Efficient AEAD cipher, particularly where AES hardware acceleration is unavailable |
| **Asymmetric key agreement / authentication with small keys** | **ECC P-256 or P-384** | Strong security with significantly smaller keys than RSA |
| **RSA where required for compatibility** | **RSA-2048 minimum; stronger sizes for greater margin** | Widely supported but less efficient than ECC |
| **Legacy algorithms to eliminate** | **DES, 3DES, RC4** | Obsolete, disallowed, or cryptographically inadequate for new protection |

---

# MedDefense Implications

The comparison highlights a direct difference between MedDefense's strong and weak cryptographic implementations. The Central-to-Westside and Central-to-HQ VPN tunnels already use **AES-256 with SHA-256, IKEv2, and DH Group 14**, which the internal audit considers adequate.

In contrast, Active Directory still permits **DES and RC4**, even though AES-128 and AES-256 Kerberos encryption are also available. MedDefense should therefore eliminate DES and RC4 after validating legacy dependencies and require AES-based Kerberos encryption.

The data-protection inventory also demonstrates where strong symmetric encryption is still absent. The EHR PostgreSQL database is unencrypted at rest, the billing MySQL database is unencrypted at rest and transmitted using plaintext MySQL, PACS images are stored and transmitted without DICOM TLS, and NAS-01 backups remain unencrypted.   

These systems are therefore the principal targets for applying the modern algorithms identified in the comparison table.

---

# Conclusion

The RSA experiment demonstrates both the advantage and limitation of asymmetric cryptography. RSA successfully encrypted the small patient record, but the 100 MB test immediately failed with a **“data too large for key size”** error, proving that RSA is unsuitable for bulk encryption.

The ECC experiment demonstrates that strong asymmetric security does not require extremely large keys. The 302-byte P-256 private-key file was approximately **5.6 times smaller** than the 1.7 KB RSA-2048 private-key file while providing approximately **128-bit security compared with RSA-2048's 112-bit security**.

These results explain the hybrid design of protocols such as TLS. Asymmetric algorithms such as RSA or ECC solve authentication and key-establishment problems, while symmetric algorithms such as AES perform the high-volume encryption efficiently.

For MedDefense, the appropriate direction is therefore to standardize on **AES for regulated-data encryption, modern ECC or sufficiently strong RSA for asymmetric functions, and the complete retirement of DES, 3DES, and RC4 from new cryptographic protection**. Existing AES-256 VPN protection provides a useful model, while the unencrypted databases, PACS traffic, backups, and legacy Active Directory cryptography identify the systems where the cryptographic baseline must be improved.
