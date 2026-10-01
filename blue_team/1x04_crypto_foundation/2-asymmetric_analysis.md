# Task 2 — The Asymmetric Engine

## Goal

Generate RSA and ECC key pairs, experimentally demonstrate the size limitation of asymmetric encryption, compare RSA and ECC key sizes, and explain why modern cryptographic systems use a hybrid combination of asymmetric and symmetric cryptography.

---

# Part 1 — RSA Key Generation and Encryption

## Generate RSA-2048 Key Pair

The following commands generate a 2048-bit RSA private key and derive its corresponding public key:

```bash
openssl genrsa -out rsa_private.pem 2048
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
```

The key files can be verified with:

```bash
ls -lh rsa_*.pem
openssl rsa -in rsa_private.pem -text -noout | head -20
```

Observed output:

```text
-rw------- 1 kali kali 1.7K Oct  1 13:37 rsa_private.pem
-rw-rw-r-- 1 kali kali  451 Oct  1 13:37 rsa_public.pem

Private-Key: (2048 bit, 2 primes)
```

The result confirms that a 2048-bit RSA key pair was successfully created. The private key contains the secret RSA parameters and must remain protected, while the public key can be distributed to systems that need to encrypt data for the owner or verify signatures.

---

## Encrypt and Decrypt with RSA

A sample MedDefense patient record was created:

```bash
echo -n "Patient: Jane Doe | DOB: 1985-03-14 | MRN: MED-50421 | Diagnosis: Atrial Fibrillation" > patient_record.txt
```

The record was encrypted using the RSA public key:

```bash
openssl pkeyutl -encrypt \
    -pubin \
    -inkey rsa_public.pem \
    -in patient_record.txt \
    -out patient_record_rsa.enc
```

The ciphertext was then decrypted using the corresponding private key:

```bash
openssl pkeyutl -decrypt \
    -inkey rsa_private.pem \
    -in patient_record_rsa.enc \
    -out patient_record_rsa.dec
```

The original and decrypted files were compared:

```bash
diff patient_record.txt patient_record_rsa.dec && echo "RSA: Files match"
```

Output:

```text
RSA: Files match
```

This demonstrates the basic asymmetric encryption model: a sender can encrypt information using the recipient's public key, while only the holder of the corresponding private key can decrypt it.

---

## Attempt to Encrypt a 100 MB File with RSA

Attempting to encrypt the large test file directly produced the following error:

```bash
openssl pkeyutl -encrypt \
    -pubin \
    -inkey rsa_public.pem \
    -in testfile \
    -out testfile_rsa.enc 2>&1
```

Output:

```text
Public Key operation error
20CD93A4FFFF0000:error:0200006E:rsa routines:ossl_rsa_padding_add_PKCS1_type_2_ex:data too large for key size:../crypto/rsa/rsa_pk1.c:132:
```

## Why RSA Cannot Encrypt Large Files

RSA operates on values smaller than its mathematical modulus, so a 2048-bit RSA key can process only a very small amount of plaintext in a single encryption operation. With the PKCS#1 v1.5 padding used in this experiment, a 2048-bit key has a 256-byte RSA block and requires at least 11 bytes of padding, leaving a maximum plaintext of approximately **245 bytes**—far less than a 100 MB file.

This means RSA is not designed for bulk file encryption. In real systems it is normally used to protect a small secret, such as a symmetric session key, while a high-speed symmetric algorithm such as AES encrypts the actual file or network traffic.

---

# Part 2 — ECC Key Generation

## Generate ECC Key Pair — P-256

The following commands generated an elliptic-curve key pair using the NIST P-256 curve, also known as `prime256v1`:

```bash
openssl ecparam -genkey -name prime256v1 -out ecc_private.pem
openssl ec -in ecc_private.pem -pubout -out ecc_public.pem
```

The keys were verified using:

```bash
ls -lh ecc_*.pem
openssl ec -in ecc_private.pem -text -noout | head -15
```

Observed output:

```text
-rw------- 1 kali kali 302 Oct  1 13:50 ecc_private.pem
-rw-rw-r-- 1 kali kali 178 Oct  1 13:50 ecc_public.pem

Private-Key: (256 bit)
ASN1 OID: prime256v1
NIST CURVE: P-256
```

The output confirms successful creation of a 256-bit P-256 elliptic-curve key pair.

---

## RSA vs. ECC Key Size Comparison

The private-key files produced by the experiment were approximately:

| Key | File Size |
|---|---:|
| RSA-2048 private key | 1.7 KB |
| ECC P-256 private key | 302 bytes |

Using the displayed file sizes:

**1,700 ÷ 302 ≈ 5.6**

Therefore, the RSA private-key file is approximately **5.6 times larger** than the ECC private-key file. Because `ls -lh` rounds the RSA size to 1.7 KB, the exact ratio will vary slightly depending on the actual byte count and PEM encoding.

ECC achieves strong security with much smaller keys because the elliptic-curve discrete-logarithm problem is substantially harder per key bit than the integer-factorization problem on which RSA depends. P-256 provides approximately **128 bits of classical security**, whereas RSA-2048 provides approximately **112 bits**, meaning the 256-bit ECC key is not merely smaller—it actually provides a higher estimated security strength than the RSA-2048 key generated in this exercise.

This efficiency is important for resource-constrained environments such as MedDefense's BD Alaris pumps and Philips IntelliVue monitors. Smaller keys reduce storage requirements, network overhead, and asymmetric computation, making ECC attractive for devices where CPU capacity, memory, power, and network bandwidth are more limited.

A more equivalent 128-bit security comparison would be approximately:

**ECC P-256 ≈ RSA-3072**

rather than RSA-2048.

---

# Part 3 — The Hybrid Model

Modern protocols combine asymmetric and symmetric cryptography because the two approaches solve different problems. During a TLS connection, asymmetric cryptography is used during the **handshake** to authenticate the server and establish shared keying material—modern TLS commonly uses ephemeral elliptic-curve Diffie-Hellman (ECDHE), authenticated by the server's certificate. Once both parties have established session keys, a symmetric cipher such as AES-GCM or ChaCha20-Poly1305 encrypts the actual application data because symmetric encryption is dramatically faster and can efficiently protect large quantities of information. This hybrid approach therefore obtains the key-distribution and authentication advantages of public-key cryptography without suffering the severe size and performance limitations demonstrated by the RSA large-file experiment. Neither approach alone provides this combination as effectively: symmetric encryption is excellent for bulk data but requires secure key establishment, while asymmetric cryptography solves key establishment and authentication but is inefficient for bulk encryption.

For the **MedDefense patient portal**, the TLS handshake performs the asymmetric authentication/key-establishment portion, after which the negotiated symmetric cipher protects patient portal traffic. The audit notes show that the portal currently supports **TLS 1.0 and TLS 1.2**, does not support TLS 1.3, and uses the default Apache cipher configuration; the exact negotiated cipher suites are not documented. Therefore, MedDefense should disable TLS 1.0, document its cipher suites, and move toward modern TLS configurations using authenticated symmetric encryption.

---

# Part 4 — Key Length Comparison Table

## Healthcare Interpretation

HIPAA does not provide a simple list declaring individual algorithms "HIPAA approved." Instead, HHS states that ePHI should be encrypted through processes consistent with appropriate NIST guidance, with decryption keys protected separately from the encrypted information.

For this table, **Approved** therefore means suitable for a modern NIST-aligned MedDefense cryptographic baseline for regulated healthcare information. **Not Approved** identifies obsolete algorithms that should not be used to apply new cryptographic protection.

| Algorithm | Type | Key Lengths | Equivalent Security | Status | MedDefense Usage |
|---|---|---|---|---|---|
| **AES** | Symmetric block cipher | 128, 192, 256 bits | 128 / 192 / 256 bits respectively | **Approved / Recommended.** AES remains a standard choice for regulated data. Modern authenticated modes such as AES-GCM should generally be preferred for new application designs. | **Currently used.** Central-to-Westside and Central-to-HQ IPSec tunnels use AES-256. NAS-01 also supports AES-256-CBC shared-folder encryption, although the feature is currently disabled.  |
| **RSA** | Asymmetric | 2048, 4096 bits | RSA-2048 ≈ **112-bit** security; RSA-4096 ≈ **149–150-bit** security | **Approved today**, when appropriately implemented. RSA should be used for authentication, signatures, or key establishment rather than bulk-data encryption. Long-term systems should also account for migration to post-quantum cryptography. | No specific RSA implementation is established in the MedDefense audit. The patient portal uses a Let's Encrypt certificate, but the audit does not document whether its public key is RSA or ECC. |
| **ECC — P-256** | Asymmetric elliptic curve | 256-bit curve | ≈ **128-bit** security | **Approved / Recommended** for current classical cryptography. Provides high security with relatively small keys. | No existing MedDefense P-256 deployment is documented. It is a strong candidate for TLS authentication/key establishment and constrained clinical devices. |
| **ECC — P-384** | Asymmetric elliptic curve | 384-bit curve | ≈ **192-bit** security | **Approved / Recommended.** Higher security strength than P-256 at additional computational cost. | No current MedDefense use documented. Could be considered where a higher security margin is required. |
| **DES** | Symmetric block cipher | 56 effective key bits | ≈ **56-bit** security | **Not Approved.** DES is cryptographically obsolete and far below modern security-strength requirements. | **Currently exposed through legacy AD compatibility.** MedDefense's domain controllers still support DES Kerberos encryption. Finding 018 requires its removal. |
| **3DES / TDEA** | Symmetric block cipher | 168 nominal bits using three keys; ≈112-bit effective strength | ≈ **112-bit** security for three-key TDEA | **Not Approved for applying new cryptographic protection.** NIST disallowed TDEA for new protection after December 31, 2023; legacy decryption/verification of previously protected data may still be allowed. | No current MedDefense 3DES deployment is documented. It should not be introduced into the new cryptographic baseline. |
| **ChaCha20-Poly1305** | Symmetric stream cipher + authenticator / AEAD | 256-bit ChaCha20 key; 128-bit authentication tag | ChaCha20 designed for **256-bit confidentiality**, with a 128-bit Poly1305 tag | **Modern and cryptographically strong, but not a NIST/FIPS-approved primitive.** It is standardized by the IETF and widely used in modern protocols, but AES-GCM is the safer default where MedDefense requires strict NIST/FIPS alignment. RFC 8439 specifies a 256-bit key and 96-bit nonce. | No current MedDefense usage documented. Could be considered only if organizational requirements permit non-FIPS algorithms; otherwise use AES-GCM. |
| **RC4** | Symmetric stream cipher | Historically variable; commonly 128 bits | No acceptable modern security strength | **Not Approved / Prohibited for TLS.** IETF requires TLS clients and servers never to negotiate RC4 cipher suites because of practical cryptographic weaknesses. | **Currently enabled in Active Directory Kerberos compatibility.** Finding 018 confirms RC4 remains enabled and permits RC4 service tickets that can facilitate Kerberoasting attacks. It should be disabled after legacy dependencies are identified. |

NIST's current guidance treats **security strength** as the amount of computational work required to break an algorithm. Modern systems should provide at least 112 bits of security today, while systems intended to remain in use beyond 2030 should target at least 128 bits.

AES-128, AES-192, and AES-256 remain acceptable modern symmetric choices, while algorithms below modern security-strength requirements should not be used. NIST also explicitly disallowed TDEA for applying new cryptographic protection after 2023.

---

# Conclusion

The experiments demonstrate the fundamental trade-off between symmetric and asymmetric cryptography. RSA successfully protected the small patient record, but immediately failed when asked to encrypt a 100 MB file because RSA can process only messages that fit within its modulus and padding limits. ECC demonstrated that asymmetric security can be achieved with dramatically smaller keys: the generated P-256 private-key file was approximately one-sixth the size of the RSA-2048 private-key file while providing a higher estimated classical security strength.

These observations explain the design of modern protocols such as TLS. Asymmetric cryptography provides authentication and secure key establishment, while symmetric algorithms such as AES handle high-volume application data efficiently. For MedDefense, this model is directly relevant to the patient portal, VPN tunnels, database connections, backup encryption, and future secure communications with clinical devices.
