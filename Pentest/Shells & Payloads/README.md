# Méthodologie des Shells & Payloads

Cette méthodologie couvre les différentes techniques pour obtenir, améliorer et maintenir des shells sur des systèmes compromis.

## Table des matières

1. [Concepts de base](#concepts-de-base)
2. [Types de shells](#types-de-shells)
   - [Reverse Shells](#reverse-shells)
   - [Bind Shells](#bind-shells)
3. [Shell Payloads](#shell-payloads)
   - [Linux/Unix](#linuxunix)
   - [Windows](#windows)
   - [Multi-plateformes](#multi-plateformes)
4. [Création avec MSFvenom](#création-avec-msfvenom)
   - [Staged vs Stageless](#staged-vs-stageless)
   - [Formats & Encodage](#formats--encodage)
5. [Web Shells](#web-shells)
   - [PHP](#php)
   - [ASP/ASPX](#aspaspx)
   - [JSP](#jsp)
6. [Amélioration des shells](#amélioration-des-shells)
   - [Techniques TTY](#techniques-tty)
   - [Stabilisation](#stabilisation)
7. [Contournement des défenses](#contournement-des-défenses)
   - [Antivirus & EDR](#antivirus--edr)
   - [Obfuscation](#obfuscation)

Chaque section décrit les techniques applicables avec des exemples pratiques pour différents environnements.