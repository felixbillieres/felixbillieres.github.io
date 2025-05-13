# Concepts de Base des Shells & Payloads

## Définitions Essentielles

### Shell
Un shell est une interface qui permet d'interagir avec le système d'exploitation. Dans le contexte des tests d'intrusion, l'objectif est d'obtenir un shell sur un système compromis pour exécuter des commandes.

### Payload
Un payload est le code qui s'exécute sur le système cible après une exploitation réussie. Il peut s'agir d'un simple shell, d'un vol d'informations ou d'actions plus complexes.

### Session
Une session est une connexion établie entre l'attaquant et la cible. Elle peut être interactive (permettant l'exécution de commandes en temps réel) ou non-interactive.

## Types de Communication

### Canaux de Données
Les shells utilisent différents canaux pour communiquer:
- **TCP/UDP**: Ports réseau standard (souvent ports élevés pour éviter la détection)
- **HTTP/HTTPS**: Communication via protocoles web (utile pour contourner les pare-feu)
- **DNS**: Communication via requêtes DNS (stéganographie réseau)
- **ICMP**: Utilisation des paquets ping pour transporter des données

### Modes d'Opération
- **Interactif**: Permet une interaction en temps réel avec le système
- **Non-interactif**: Exécution de commandes sans attendre de réponse immédiate
- **Semi-interactif**: Mélange des deux approches précédentes

## Identification du Système Cible

Avant d'utiliser un shell, il est crucial d'identifier correctement le système cible:

### Empreinte OS via TTL
```bash
# Windows: TTL=128, Linux: TTL=64
ping -c 1 $TARGET_IP | grep ttl
```

### Détection via Nmap
```bash
# Détection de l'OS
sudo nmap -O $TARGET_IP

# Détection des services et bannières
sudo nmap -sV -sC $TARGET_IP
```

### Reconnaissance Web
```bash
# Analyse des headers
curl -I $TARGET_URL

# Recherche d'indices dans le code source
curl -s $TARGET_URL | grep -i "windows\|linux\|ubuntu\|apache\|nginx"
```

## Considérations de Sécurité

### Logs et Traces
Les shells laissent des traces dans différents endroits:
- Logs de connexion
- Logs d'application
- Historique de commandes

### OPSEC (Operational Security)
- Limiter la durée des sessions
- Utiliser des ports courants (80, 443) pour se fondre dans le trafic légitime
- Éviter les actions bruyantes (scans massifs, créations multiples de fichiers)
- Considérer l'encodage et le chiffrement des communications