# Task 4 — The Key Exchange

## Goal

Simulate a Diffie-Hellman key exchange with OpenSSL to understand how two parties can independently derive the same shared secret over an insecure network, then analyze the man-in-the-middle weakness that authentication and certificates are designed to solve.

---

# Part 1 — Diffie-Hellman Simulation

## 1. Generate Shared DH Parameters

Alice and Bob must first agree on common Diffie-Hellman parameters. These parameters are public and can safely be shared.

```bash
openssl dhparam -out dhparams.pem 2048
```

Observed output:

```text
Generating DH parameters, 2048 bit long safe prime
..................................
```

The generated parameters were inspected with:

```bash
openssl dhparam -in dhparams.pem -text -noout
```

Observed output:

```text
DH Parameters: (2048 bit)

P:
    00:d2:27:f1:a7:58:19:b6:32:0c:d9:e5:eb:af:40:
    df:32:0e:92:3c:8d:9e:a3:f5:c1:12:6b:26:73:f0:
    e4:c5:87:9a:ea:cf:78:6a:5d:c0:8f:1e:1b:b8:b9:
    9d:f7:a4:b1:1f:ab:18:60:7d:53:fd:c5:9c:86:73:
    d0:39:c0:fb:fe:c8:d5:2d:50:16:9f:25:d8:c7:a1:
    f9:39:d3:d5:f4:38:11:c9:61:8f:63:23:c8:ff:c5:
    8e:72:5e:df:fb:a5:3a:65:21:25:13:00:b6:0b:f1:
    a3:48:9d:37:15:ef:f0:9e:5a:af:88:f2:e3:ed:b4:
    30:51:e9:74:4e:8b:2c:35:ed:2d:fc:e8:ab:1b:2f:
    77:3e:1f:cf:5f:5d:98:41:79:aa:c4:91:2f:de:f8:
    72:54:fe:63:41:70:ad:03:1a:52:98:b5:6e:c0:13:
    49:7d:cd:3a:3b:36:1d:0d:11:da:fe:48:9d:52:4b:
    24:52:5a:15:75:ab:7f:61:af:3e:87:7c:af:d5:fb:
    1b:84:46:e1:7b:e9:3c:6c:5e:d8:d3:c7:f2:ad:c3:
    6d:18:d2:b4:c0:26:7c:78:b3:e4:b6:0c:02:c4:c4:
    ba:9a:c9:63:59:76:ce:fc:1c:40:17:e2:c0:51:e1:
    a0:a4:a7:e7:74:a4:61:2c:d8:46:82:bf:5c:85:81:
    ec:5f

G: 2 (0x2)

recommended-private-length: 225 bits
```

The output confirms that OpenSSL successfully created a **2048-bit Diffie-Hellman parameter set**.

The two important public values are:

- **P** — a large prime modulus.
- **G** — the generator, which in this case is `2`.

These values do not need to be secret.

---

## 2. Generate Alice's Private Key

Alice generates her own private Diffie-Hellman key using the shared parameters:

```bash
openssl genpkey \
    -paramfile dhparams.pem \
    -out alice_dh_priv.pem
```

The command completes without terminal output when successful.

The generated files were checked using:

```bash
ls -la
```

Observed output:

```text
total 16
drwxrwxr-x 2 kali kali 4096 Oct  1 22:03 .
drwxr-xr-x 4 kali kali 4096 Oct  1 22:03 ..
-rw------- 1 kali kali  806 Oct  1 22:03 alice_dh_priv.pem
-rw-rw-r-- 1 kali kali  428 Oct  1 22:03 dhparams.pem
```

Alice's private key is stored in:

```text
alice_dh_priv.pem
```

Unlike the DH parameters, this file must remain secret.

---

## 3. Extract Alice's Public Key

Alice derives her public key from her private key:

```bash
openssl pkey \
    -in alice_dh_priv.pem \
    -pubout \
    -out alice_dh_pub.pem
```

The command completes without terminal output when successful.

Alice's public key was inspected using:

```bash
openssl pkey \
    -in alice_dh_pub.pem \
    -pubin \
    -text \
    -noout
```

Observed output begins:

```text
DH Public-Key: (2048 bit)

public-key:
    5a:97:a1:91:45:67:76:0a:cb:74:c3:aa:04:92:6c:
    e0:71:69:1b:03:90:8c:5b:59:28:73:22:a3:9c:05:
    c2:a6:79:85:a9:e1:b4:13:d3:7e:84:2d:53:28:ee:
    6c:49:0c:4d:33:38:2f:3b:e1:86:64:54:f9:9f:08:
    b7:fa:84:b8:eb:e7:40:bd:c7:53:88:44:bb:b8:f8:
    bb:88:cb:ff:82:76:f7:ac:02:8f:58:28:ff:a9:e2:
    c0:88:ca:9d:1b:55:e8:e2:5c:f7:d6:4d:58:2e:51:
    a7:81:e4:f8:54:4b:43:50:33:3d:8a:e7:ba:4c:43:
    54:f6:bd:f1:5c:65:33:c6:31:85:5f:63:98:5a:6c:
    20:bb:89:e0:b7:10:87:f5:21:f2:1d:f2:20:d1:1a:
    fe:d3:f9:d7:37:0d:c7:dd:e7:93:7b:c6:c6:81:9f:
    5a:de:50:7b:43:8c:e2:f8:06:df:48:d7:a7:68:1f:
    8e:85:8b:ef:4e:ff:8e:5f:f5:86:b8:10:2e:0c:a1:
    0e:3a:42:72:1c:73:db:3f:33:cf:51:81:bc:f0:80:
    1a:8b:23:00:45:97:5d:ef:e8:90:59:36:7e:d3:85:
    ea:d0:9e:a8:90:e6:d7:ed:b1:61:94:a9:c3:7b:d9:
    e8:d2:00:e5:33:ee:3e:71:b1:c2:bc:b4:d7:2b:5d:
    da
```

The public-key output also contains the same DH parameters `P` and `G` generated earlier.

Alice can safely send:

```text
alice_dh_pub.pem
```

to Bob.

She must never send:

```text
alice_dh_priv.pem
```

---

## 4. Generate Bob's Private Key

Bob independently creates his own private key from the same DH parameters:

```bash
openssl genpkey \
    -paramfile dhparams.pem \
    -out bob_dh_priv.pem
```

The command completes successfully without terminal output.

Bob's private key is unique and independent from Alice's private key.

---

## 5. Extract Bob's Public Key

Bob derives his public key:

```bash
openssl pkey \
    -in bob_dh_priv.pem \
    -pubout \
    -out bob_dh_pub.pem
```

Bob's public key was inspected using:

```bash
openssl pkey \
    -in bob_dh_pub.pem \
    -pubin \
    -text \
    -noout
```

Observed output begins:

```text
DH Public-Key: (2048 bit)

public-key:
    00:b9:37:4d:85:13:c7:b6:06:dc:5b:44:e6:cf:02:
    1a:c0:4d:b6:ea:78:f2:d9:61:d8:cd:ef:47:d0:da:
    9d:6b:74:64:2a:3c:20:60:27:b2:4f:07:81:a8:e0:
    37:f1:31:25:29:28:37:5c:bf:41:cc:a1:3d:61:fc:
    98:ce:d6:c1:a3:8c:e8:d6:16:31:b8:fe:f6:2b:f4:
    8b:9f:31:9c:dc:d1:ed:4f:23:9d:6a:20:20:1d:3c:
    10:91:b1:9d:55:4c:fd:44:67:6a:93:97:22:4c:a3:
    ba:70:f6:36:ea:8d:b5:57:d1:f6:c7:f5:fb:7e:88:
    c3:62:09:dd:48:46:2d:b4:48:3c:41:ce:7b:6f:4a:
    83:a3:42:5e:32:cf:b2:5c:a9:52:ac:0d:9c:8e:45:
    fc:83:45:84:38:d2:29:8f:ad:b7:c4:26:3f:a7:d3:
    c0:7d:8f:01:49:79:72:0e:cd:69:9c:24:ae:c4:f5:
    6c:77:d8:ae:d7:7f:3f:e3:c2:89:8e:13:91:11:2a:
    4a:25:ca:20:d4:18:54:4d:57:e8:ff:4f:30:59:37:
    47:cc:24:45:18:50:58:6e:7c:ff:6e:7d:9b:de:b2:
    03:9d:e4:5d:d6:cf:e2:21:81:03:2d:ca:25:4e:c8:
    40:5b:3f:db:94:2e:70:d7:bc:52:f5:fb:62:f7:ae:
    d6:55
```

As expected, Bob's public key is different from Alice's because each participant generated a different private key.

However, both public keys use the same shared DH parameters.

---

## 6. Alice Derives the Shared Secret

Alice now combines:

- her **private key**, and
- Bob's **public key**

to calculate the shared secret:

```bash
openssl pkeyutl \
    -derive \
    -inkey alice_dh_priv.pem \
    -peerkey bob_dh_pub.pem \
    -out alice_secret.bin
```

The command completes successfully without terminal output.

Alice's derived secret is stored in:

```text
alice_secret.bin
```

---

## 7. Bob Derives the Shared Secret

Bob performs the reverse operation using:

- his **private key**, and
- Alice's **public key**

```bash
openssl pkeyutl \
    -derive \
    -inkey bob_dh_priv.pem \
    -peerkey alice_dh_pub.pem \
    -out bob_secret.bin
```

Bob's derived secret is stored in:

```text
bob_secret.bin
```

---

## 8. Compare the Shared Secrets

The two independently generated files were compared:

```bash
diff alice_secret.bin bob_secret.bin && \
echo "MATCH: Shared secrets are identical"
```

Observed output:

```text
MATCH: Shared secrets are identical
```

This is the key result of the experiment.

Alice and Bob:

- generated different private keys,
- generated different public keys,
- never transmitted a shared secret,
- and still independently calculated the **same secret value**.

---

## Part 1 Results Summary

| Component | Alice | Bob | Secret? |
|---|---|---|---|
| DH parameters | Same `P` and `G` | Same `P` and `G` | No |
| Private key | `alice_dh_priv.pem` | `bob_dh_priv.pem` | **Yes** |
| Public key | `alice_dh_pub.pem` | `bob_dh_pub.pem` | No |
| Peer public key received | Bob's public key | Alice's public key | No |
| Derived secret | `alice_secret.bin` | `bob_secret.bin` | **Yes** |
| Final result | Shared secrets match | Shared secrets match | **Yes** |

### Result

**Diffie-Hellman successfully allowed Alice and Bob to agree on an identical shared secret without transmitting that secret across the network.**

---

# Part 2 — The Explanation

Alice and Bob started with the same public Diffie-Hellman parameters, then each generated a private key that was never shared with anyone. From those private keys, each created a public key that could safely be sent across the network. Alice combined her private key with Bob's public key, while Bob combined his private key with Alice's public key, and the mathematics of Diffie-Hellman caused both calculations to produce the same shared secret. The successful `diff alice_secret.bin bob_secret.bin` command confirmed that the two independently derived secrets were identical. An eavesdropper such as Eve could see the DH parameters and both public keys travelling across the network, but she would not see either private key. Without one of those private values, deriving the shared secret from the public information alone is computationally infeasible when sufficiently strong Diffie-Hellman parameters are used.

The central idea can be summarized as:

```text
                 Public DH Parameters
                      P and G
                         │
              ┌──────────┴──────────┐
              │                     │
            Alice                  Bob
              │                     │
       Private Key A         Private Key B
              │                     │
              ▼                     ▼
       Public Key A          Public Key B
              │                     │
              └────── exchanged ────┘
              │                     │
              ▼                     ▼
 Private A + Public B   Private B + Public A
              │                     │
              └──────────┬──────────┘
                         ▼
                 SAME SHARED SECRET
```

The important point is that the **shared secret itself never crosses the network**.

An eavesdropper can observe:

```text
DH Parameters
Alice's Public Key
Bob's Public Key
```

but cannot observe:

```text
Alice's Private Key
Bob's Private Key
Derived Shared Secret
```

This is how Diffie-Hellman solves the symmetric-key distribution problem.

---

# Part 3 — The Man-in-the-Middle Attack

Diffie-Hellman provides a way to establish a shared secret, but plain Diffie-Hellman does **not authenticate the participants**.

If Eve can actively intercept and modify traffic, she can intercept Alice's public key before it reaches Bob and replace it with her own public key. She can do the same to Bob's public key before it reaches Alice. Alice then unknowingly establishes a shared secret with Eve, while Bob establishes a different shared secret with Eve. Because Eve possesses both secrets, she can decrypt Alice's messages, inspect or modify them, encrypt them again using Bob's secret, and forward them to Bob.

The attack can be represented as:

```text
Normal Diffie-Hellman

Alice  ─────────────── Public Key A ───────────────► Bob
Alice  ◄────────────── Public Key B ──────────────── Bob

                    Shared Secret
                         ✓
```

With an active attacker:

```text
                    Eve
                   /   \
                  /     \
                 ▼       ▼

Alice          Secret 1         Secret 2           Bob
  │                ▲                ▲                │
  │                │                │                │
  └──── DH ─────── Eve ──────── DH ────────────────┘

Alice believes she is talking to Bob.
Bob believes he is talking to Alice.

Both are actually exchanging keys with Eve.
```

The encryption itself can still be mathematically strong. The failure is that neither Alice nor Bob has proven **who owns the public key they received**.

---

## MedDefense VPN Connection

This attack model is directly relevant to the site-to-site connection between MedDefense Central and Westside Clinic.

The MedDefense audit confirms that the tunnel currently uses:

- **IPSec**
- **AES-256 encryption**
- **SHA-256 integrity**
- **IKEv2**
- **Diffie-Hellman Group 14**

for its cryptographic configuration.

The audit also notes that the Westside end of the connection terminates on a Netgear consumer router with an unknown firmware-update history.

However, the available evidence does **not** state whether MedDefense authenticates its IKEv2 VPN endpoints using:

- certificates,
- a pre-shared key,
- or another authentication mechanism.

Therefore, it would be inaccurate to state that the existing MedDefense tunnel is vulnerable because it uses unauthenticated Diffie-Hellman.

The correct scenario is hypothetical:

> If the Central-to-Westside VPN performed Diffie-Hellman key exchange without securely authenticating the two endpoints, an attacker positioned on the network path could attempt to impersonate both sides, negotiate independent shared secrets with each endpoint, and act as a man in the middle.

---

# How Certificates Prevent the Attack

Certificates add something that basic Diffie-Hellman does not provide:

## Identity

A digital certificate binds:

```text
An identity
     +
A public key
     +
A trusted issuer's digital signature
```

When Alice receives Bob's public key through an authenticated protocol using certificates, she does not simply ask:

> "Can I mathematically create a secret with this public key?"

She can also verify:

> "Does this public key actually belong to Bob?"

The certificate is signed by a trusted Certificate Authority, allowing Alice to verify the identity associated with the public key.

An attacker such as Eve can still generate her own private and public keys, but she cannot produce a valid certificate identifying herself as Bob unless she can obtain a trusted certificate or compromise the relevant certificate infrastructure.

Therefore, authenticated key exchange provides both:

```text
Diffie-Hellman
      │
      ▼
Shared Secret
```

and:

```text
Certificate / Authentication
      │
      ▼
Verified Identity
```

Together:

```text
       AUTHENTICATED KEY EXCHANGE

       Identity             Key Exchange
           │                     │
     Certificate            Diffie-Hellman
           │                     │
           └─────────┬───────────┘
                     ▼
         Authenticated Shared Secret
                     │
                     ▼
             Symmetric Encryption
```

This is the principle behind secure protocols such as TLS and authenticated VPN protocols.

---

# Final Analysis

The laboratory demonstrates that Diffie-Hellman solves one of the central problems of symmetric cryptography: **how two parties can establish the same secret without transmitting that secret directly**.

Alice and Bob independently generated private keys, exchanged only public information, and then calculated identical shared secrets. The successful result:

```text
MATCH: Shared secrets are identical
```

confirms that the exchange worked.

However, the experiment also demonstrates an equally important limitation. Diffie-Hellman establishes a secret, but plain Diffie-Hellman does not establish **identity**. An active attacker can potentially substitute public keys and perform separate exchanges with both legitimate participants.

This creates an important distinction:

| Security Requirement | Technology |
|---|---|
| Establish a shared secret | Diffie-Hellman |
| Prove the identity of the peer | Certificates / authentication |
| Encrypt large amounts of traffic | Symmetric encryption such as AES |
| Protect message integrity | Authentication/integrity mechanism such as AEAD or MAC |

For MedDefense, this relationship is directly relevant to the Central-to-Westside VPN. The existing tunnel already uses strong cryptographic components such as AES-256, SHA-256, IKEv2, and DH Group 14, but the cryptographic baseline should also explicitly define how VPN endpoints are authenticated.

The experiment therefore demonstrates the progression used throughout modern cryptography:

**Key exchange establishes the secret. Authentication establishes who is on the other side. Symmetric encryption then protects the actual data.**
