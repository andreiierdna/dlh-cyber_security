# Task 3 — The Hash Laboratory

## Goal

Explore cryptographic hashing through practical experimentation, observe the avalanche effect, understand collision resistance and rainbow tables, compare modern password-hashing mechanisms, and create a SHA-256 integrity verification script.

Hashing differs fundamentally from encryption. Encryption is reversible when the correct key is available, while a cryptographic hash function produces a fixed-length, one-way representation of its input. This distinction is particularly important for MedDefense because passwords should not be stored in a recoverable form, and weak password-hashing mechanisms can allow an attacker who obtains password hashes to perform offline cracking attacks.

---

# Part 1 — The Avalanche Effect

## SHA-256

Hash the string `MedDefense`:

```bash
echo -n "MedDefense" | sha256sum
```

Output:

```text
39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c8671098  -
```

Hash `MedDefense1`, which differs by only one additional character:

```bash
echo -n "MedDefense1" | sha256sum
```

Output:

```text
97a4141d69cc726a7f6ef577df588d4010c3fe4f235a8bdb616732ba9bf17b92  -
```

## MD5

Hash `MedDefense` using MD5:

```bash
echo -n "MedDefense" | md5sum
```

Output:

```text
75d47fd4b4d183456d0f98fd9ba6ae4d  -
```

Hash `MedDefense1`:

```bash
echo -n "MedDefense1" | md5sum
```

Output:

```text
0d2aed72043f78c2935e61ba8520306d  -
```

## Hash Comparison

| Algorithm | `MedDefense` | `MedDefense1` | Different Hex Characters | Different Output Bits |
|---|---|---|---:|---:|
| **SHA-256** | `39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c8671098` | `97a4141d69cc726a7f6ef577df588d4010c3fe4f235a8bdb616732ba9bf17b92` | **62 of 64** | **131 of 256 = 51.2%** |
| **MD5** | `75d47fd4b4d183456d0f98fd9ba6ae4d` | `0d2aed72043f78c2935e61ba8520306d` | **30 of 32** | **71 of 128 = 55.5%** |

For SHA-256, **62 of the 64 hexadecimal characters differ**, while for MD5, **30 of the 32 hexadecimal characters differ**.

The hexadecimal-character comparison is visually useful, but the avalanche effect is more accurately measured at the **bit level**. SHA-256 changed **131 of 256 bits, approximately 51.2%**, and MD5 changed **71 of 128 bits, approximately 55.5%**. These results demonstrate the avalanche effect: a very small change to the input produces a substantially different and unpredictable hash output.

The avalanche effect alone does **not** mean that a hash algorithm is secure. MD5 demonstrates a strong avalanche effect in this experiment but is nevertheless cryptographically obsolete because practical collision attacks exist.

---

# Part 2 — Hash Collisions and the Birthday Problem

MD5 produces a **128-bit** output.

Therefore, the total number of theoretically possible MD5 hash values is:

**2¹²⁸**

Approximately:

**3.4 × 10³⁸ possible outputs**

SHA-256 produces a **256-bit** output.

Therefore, the total number of theoretically possible SHA-256 outputs is:

**2²⁵⁶**

Approximately:

**1.16 × 10⁷⁷ possible outputs**

## Collision Comparison

A collision occurs when two different inputs produce the same hash value. Because MD5 has only 128 output bits while SHA-256 has 256, MD5 has a much smaller output space and is inherently more susceptible to collisions.

The birthday problem shows that an attacker does not generally need to test every possible output to find a collision. For an ideal `n`-bit hash function, a collision can be expected after approximately:

**2ⁿ⁄² operations**

Therefore:

| Algorithm | Output Size | Possible Outputs | Generic Collision Work |
|---|---:|---:|---:|
| **MD5** | 128 bits | 2¹²⁸ | approximately **2⁶⁴** |
| **SHA-256** | 256 bits | 2²⁵⁶ | approximately **2¹²⁸** |

A shorter digest therefore reduces the theoretical work needed for a collision attack. In addition, MD5 has known structural weaknesses that make practical collision creation substantially easier than an ideal 128-bit hash would suggest.

## Connection to MedDefense Finding 018

Finding 018 in the MedDefense vulnerability scan confirms that the domain controllers continue to support **DES and RC4 Kerberos encryption**, even though AES-128 and AES-256 are also available. The scan specifically identifies the weak encryption types as susceptible to offline cracking and Kerberoasting.

Microsoft documents the Kerberos RC4 option as `RC4_HMAC_MD5`. The practical security problem is not primarily an MD5 **collision** attack; rather, an attacker can request RC4-encrypted service tickets and perform password guesses offline against them. If MedDefense service accounts use weak or predictable passwords, an attacker can test large numbers of password candidates without triggering normal online login protections, making service-account compromise significantly more practical.

MedDefense should therefore remove DES and RC4 compatibility after identifying any legacy dependencies and require AES-based Kerberos encryption.

---

# Part 3 — Rainbow Table Demonstration

## Unsalted MD5

Hash the password `password123`:

```bash
echo -n "password123" | md5sum
```

Output:

```text
482c811da5d5b4bc6d497ffa98491e38  -
```

A lookup of:

```text
482c811da5d5b4bc6d497ffa98491e38
```

on CrackStation returned:

```text
Result: password123
Cracked instantly
```

The password was recovered because the unsalted MD5 value already existed in a precomputed database.

---

## Salted MD5

Add the salt `s4lt9xQ2` before hashing the password:

```bash
echo -n "s4lt9xQ2:password123" | md5sum
```

Output:

```text
6d537fa53f1db2c22b0451ef4ef9fbe8  -
```

The CrackStation lookup returned:

```text
Result: Not found
```

## Why Salting Defeats Rainbow Tables

A salt is a random value combined with a password before the password hash is calculated. Because the salt changes the hash output, a precomputed hash for `password123` cannot automatically be reused against `s4lt9xQ2:password123`.

Every user should receive a **different, randomly generated salt**. If two users have the same password but different salts, their resulting password hashes will still be different, forcing an attacker to attack each account separately instead of calculating one password hash and comparing it against the entire database. Modern password-hashing algorithms therefore incorporate unique salts as a fundamental protection against rainbow-table and precomputation attacks.

However, the experiment does **not** make MD5 suitable for password storage. The salt prevents effective precomputed rainbow-table use, but MD5 remains extremely fast, so an attacker who knows the salt can still perform large numbers of password guesses very quickly.

The appropriate design is therefore:

```text
Password
   +
Unique random salt
   +
Slow password-hashing function
   +
Configurable work factor
```

rather than:

```text
MD5(password)
```

or even:

```text
MD5(salt + password)
```

---

# Part 4 — Key Stretching

A normal cryptographic hash such as SHA-256 is intentionally designed to be fast. This is desirable for file integrity verification but undesirable for password storage because an attacker with a stolen password database can perform enormous numbers of guesses offline.

Password-hashing functions deliberately make each guess expensive through **key stretching**.

Current password-storage guidance recommends salted, computationally expensive password hashing and favors memory-hard algorithms where possible.

## bcrypt

bcrypt is a password-hashing function designed to be deliberately slower than ordinary hashes such as MD5 or SHA-256. It automatically incorporates a salt and repeatedly applies an expensive Blowfish-based key setup operation, increasing the amount of computation required for every password guess.

bcrypt uses a **cost factor**, also called a work factor, which controls its computational expense. Increasing the cost increases the number of internal operations exponentially, so legitimate password verification becomes somewhat slower while large-scale attacker brute-force attempts become considerably more expensive.

OWASP currently treats bcrypt primarily as a **legacy password-storage choice** where newer algorithms such as Argon2id are unavailable and recommends a work factor of at least 10.

---

## PBKDF2

PBKDF2, or **Password-Based Key Derivation Function 2**, combines a password, a unique salt, and a pseudorandom function such as HMAC-SHA-256. Rather than hashing the password once, PBKDF2 repeatedly applies its underlying function many times.

Its primary configurable parameter is the **iteration count**. Every additional iteration increases the amount of CPU work required to verify a password, making each offline password guess more expensive for an attacker.

PBKDF2 is especially useful where NIST/FIPS-aligned implementations are required. OWASP currently recommends **PBKDF2-HMAC-SHA256 with 600,000 or more iterations** when FIPS-140 compliance is required. NIST also describes PBKDF2 as a password-based key derivation mechanism using a salt and iteration count.

---

## Argon2

Argon2 is a modern password-hashing algorithm designed specifically to make large-scale cracking expensive not only in CPU time but also in **memory usage**. The preferred password-storage variant is **Argon2id**, which combines defenses against GPU-based attacks and certain side-channel attacks.

Instead of having only one work-factor setting, Argon2id allows configuration of:

- **Memory cost (`m`)** — how much RAM a hash operation requires.
- **Time cost (`t`)** — how many processing iterations are performed.
- **Parallelism (`p`)** — the number of processing lanes that may operate simultaneously.

Making password guesses consume significant memory is important because GPUs and specialized cracking hardware gain much of their advantage by performing thousands of simple calculations in parallel. Argon2id makes this parallelization significantly more expensive.

OWASP currently recommends Argon2id as the preferred general-purpose password hashing algorithm, with one minimum configuration being approximately **19 MiB memory, 2 iterations, and parallelism of 1**.

---

## Comparison

| Feature | bcrypt | PBKDF2 | Argon2id |
|---|---|---|---|
| Designed for password storage | Yes | Yes / key derivation | Yes |
| Unique salt | Yes | Yes | Yes |
| Adjustable work factor | Yes | Yes | Yes |
| CPU-hard | Yes | Yes | Yes |
| Memory-hard | Limited | No | **Yes** |
| Main tuning parameter | Cost/work factor | Iteration count | Memory + time + parallelism |
| GPU resistance | Better than fast hashes | Moderate | **Strong** |
| FIPS-friendly implementations | Possible but not primary modern choice | **Yes** | Usually not the choice for strict FIPS environments |
| Current preferred use | Legacy applications | FIPS/NIST-constrained applications | **Modern applications** |

---

# Recommended Password Storage for MedDefense

For a new MedDefense application, I would recommend **Argon2id** for password storage because it is intentionally memory-hard as well as computationally expensive, giving it stronger resistance to GPU and specialized password-cracking hardware than conventional fast hashes or CPU-only stretching mechanisms. Each password should receive a unique random salt, and the memory/time parameters should be selected so authentication remains acceptable for legitimate users while making offline attacks expensive.

If MedDefense has a requirement to use a **FIPS-validated cryptographic implementation**, PBKDF2-HMAC-SHA256 would be the more appropriate choice, configured with a strong iteration count. The password-storage algorithm and its work parameters should also be designed so they can be upgraded as hardware capabilities increase.

---

# What Does Active Directory Use?

Active Directory does **not** use Argon2, bcrypt, or PBKDF2 as its standard Windows password representation.

Microsoft documents the **NT hash** as the MD4 hash of the user's password. It is retained for Windows authentication compatibility and, importantly, it is **not salted**.

Conceptually:

```text
Password
   │
   ▼
MD4
   │
   ▼
NT Hash
```

rather than:

```text
Password
   │
   ├── Unique salt
   │
   ▼
Argon2id / PBKDF2 / bcrypt
   │
   ▼
Slow password verifier
```

By modern application password-storage standards, an unsalted, fast MD4-derived NT hash is **not adequate as a standalone password-hashing design**. It permits attackers who obtain the credential database or equivalent credential material to perform offline password guessing efficiently.

This is particularly relevant to MedDefense because Finding 018 also confirms that **RC4 remains enabled for Kerberos alongside AES-128 and AES-256**. MedDefense cannot simply replace Active Directory's NT hash implementation with Argon2id because it is part of Windows authentication compatibility, so the practical response is to strengthen the surrounding identity architecture: eliminate DES/RC4 dependencies, reduce NTLM use where possible, require strong passwords, deploy MFA for privileged access, protect domain controllers, and prevent attackers from obtaining credential material in the first place.

---

# Part 5 — Integrity Verification Script
