---
title: "Reading Code for Vulnerabilities: What Actually Worked for Me"
date: 2026-07-01
draft: false
description: "I wanted to get better at security code review for CTFs, research, and real work. This is the methodology I landed on: taint analysis as the mental backbone, a structured vulnerability taxonomy, and a practice repo with 20 exercises that made findings actually stick."
summary: "I wanted to get better at reading code for security issues - not just knowing vulnerability names, but being able to sit down in front of an unfamiliar codebase and find things systematically. This is what I tried, what worked, and the mental model I ended up building around taint analysis. Python-first, but the approach transfers."
tags: ["code-review", "python", "security", "vulnerability-research", "taint-analysis", "whitebox", "appsec", "learning"]
categories: ["Security", "Learning"]
featuredImage: "featured.png"
---

## Table of Contents

1. [Where this started](#where-this-started)
2. [The repo](#the-repo)
3. [The mental model: taint analysis](#the-mental-model-taint-analysis)
4. [What I chose to cover and why](#what-i-chose-to-cover-and-why)
5. [The exercises](#the-exercises)
6. [How I actually work through a piece of code](#how-i-actually-work-through-a-piece-of-code)
7. [Where SAST fits in](#where-sast-fits-in)
8. [Sources](#sources)

---

## Where this started

A while ago I noticed a gap in how I approached security work. I was reasonably comfortable with CTF challenges and web pentest methodology, but when I sat down with an unfamiliar codebase and needed to find real issues, I felt slow and unsystematic. I would scan from top to bottom, catch the obvious things, miss the subtle ones, and have no good way to know whether I had actually covered the attack surface or just read the code.

The gap is not about knowing what SQL injection is. Most people doing security work know what SQL injection is. The gap is about being able to look at three hundred lines of a Flask service with interconnected handlers and find the issues reliably, in a reasonable amount of time, with a defensible sense of coverage when you are done.

So I built a structured practice setup: theory first, then exercises against realistic broken services, then a review pass against reference solutions. This article is about that process - the mental model that ended up being useful, why I picked the vulnerability classes I did, and how the exercises are structured.

---

## The repo

Everything is at [github.com/felixbillieres/python_code_review](https://github.com/felixbillieres/python_code_review).

```
python_code_review/
├── theorie/          # 7 theory modules
├── exercices/        # 20 Python services to audit
└── solutions/        # Reference solutions with PoC payloads
```

**Theory modules** cover vulnerability classes progressively, from patterns Bandit catches automatically to JWT confusion attacks and ML supply chain issues. Each section includes how to identify the pattern in a codebase, how to exploit it, and the correct fix (useful to know in order to evaluate whether a patch actually fixes the underlying issue).

**Exercises** are 20 standalone Python files, each representing a fictional web service or worker with intentional vulnerabilities. Difficulty goes from beginner (one or two obvious issues, short data flow) to expert (vulnerability chains requiring understanding of business logic, concurrency, or multi-tenant isolation). The services use Flask, FastAPI, Django, and asyncio - realistic frameworks, not toy examples.

**Solutions** are reference documents that list all findings, walk through the exploitation for each one, and show the fix.

---

## The mental model: taint analysis

The first thing I tried was memorizing a list of vulnerability patterns. That worked at the level of recognition but not analysis. I could spot `pickle.loads(data)` or `subprocess.Popen(..., shell=True)` when they appeared in obvious form, but I would miss the same vulnerability when it was split across a helper function and a caller, or when the sink was reached through a slightly unusual path.

What changed was committing to a single mental model for every review: **taint analysis**. It comes from static analysis research but reduces to four concepts in practice: sources, propagation, sinks, and sanitizers.

**Sources** are where external data enters the system. In a web application: HTTP request parameters, headers, body content, URL path segments, cookies, uploaded file contents. More generally: environment variables, files read from disk, responses from external services, database content written by untrusted actors.

**Sinks** are where data is consumed in a way that can cause harm if the data is malicious. A database query assembled by string concatenation is a SQLi sink. A shell command built from user input is a command injection sink. A file path passed to `open()` is a path traversal sink. A Jinja2 template rendered from user input is an SSTI sink. Sinks are finite and can usually be enumerated quickly.

**Propagation** is what happens between source and sink: assignments, function calls, string concatenations, format operations. The question is whether data from a given source reaches a given sink, and in what form.

**Sanitizers** are operations that should transform tainted data into safe data before it reaches a sink. The critical question about any sanitizer is not whether it exists but whether it is the right sanitizer for the specific sink, and whether it is applied at the right point in the propagation chain.

The model turns a vague question ("is this code vulnerable?") into a structured checklist ("for each sink in this code, trace backwards to its sources and check whether the propagation chain passes through an appropriate sanitizer").

**Direction matters.** Forward analysis starts at sources and follows data forward to see which sinks it reaches. Backward analysis starts at sinks and traces backwards to find sources. In a timed review, backward analysis is almost always faster. Sinks are few and easy to spot. Sources are many and harder to enumerate completely.

**The most common real-world failure: sanitizer in the wrong place.** A sanitizer that runs before a transformation that invalidates it protects nothing. The pattern appears constantly in exercises - and in real code:

```python
raw = request.get_json()["payload"]
# sanitizer runs on the base64-encoded string
if contains_malicious_patterns(raw):
    abort(400)
decoded = base64.b64decode(raw)
result = yaml.load(decoded)   # RCE sink - sanitizer checked the wrong form
```

The sanitizer scans the base64-encoded version of the payload. The YAML deserializer runs on the decoded bytes. A payload that looks clean when encoded bypasses the check entirely.

---

## What I chose to cover and why

The theory modules are ordered roughly by how easy the vulnerability is to spot without context. Module 00 covers things that appear in a grep or a Bandit scan. By module 05 you need to understand JWT cryptographic primitives to recognize the issue.

### Module 00: Visible patterns

**[theorie/00-patterns-visibles.md](https://github.com/felixbillieres/python_code_review/blob/main/theorie/00-patterns-visibles.md)**

`eval(user_input)`, `subprocess.run(..., shell=True)`, hardcoded API keys, `verify=False` on TLS, `debug=True` in Flask. These are the quick wins in any audit - a `bandit -r .` catches all of them.

In a real pentest, these show up in DevOps scripts, CI/CD workers, and internal tooling that has never been code-reviewed. They are also the issues that make the client uncomfortable, because they are hard to justify: there is no architectural reason to have `eval` on a user-controlled string.

**Relevant exercises:** [01-user-file-service](https://github.com/felixbillieres/python_code_review/blob/main/exercices/01-user-file-service.py) packs several of these into a single service alongside subtler issues.

---

### Module 01: Classic injections and weak crypto

**[theorie/01-injections-classiques.md](https://github.com/felixbillieres/python_code_review/blob/main/theorie/01-injections-classiques.md)**

SQL injection, argument injection (the `shell=False` version where a user-controlled string becomes a dangerous flag), weak password hashing, predictable tokens from `random` instead of `secrets`, and timing attacks via `==` on secret values.

SQL injection is CWE #3 in the 2024 Top 25. It remains present in production APIs because ORMs give a false sense of safety - Django's `.extra()`, SQLAlchemy's `text(f"...")`, and raw query helpers remain injectable even when the rest of the ORM is correctly parameterized.

Argument injection is the one most scanners miss. When `subprocess.run` has `shell=False` but the user controls the argument list, options like `--upload-pack=` (git) or `-o /etc/cron.d/x` (curl) can still cause serious issues.

**Relevant exercises:** [05-invoice-import](https://github.com/felixbillieres/python_code_review/blob/main/exercices/05-invoice-import.py) has a second-order SQLi that only appears once you trace a stored value back to a later query. [12-auth-and-reset](https://github.com/felixbillieres/python_code_review/blob/main/exercices/12-auth-and-reset.py) chains a weak reset token with a JWT issue into a full account takeover.

---

### Module 02: Deserialization and parsing

**[theorie/02-deserialisation-parsing.md](https://github.com/felixbillieres/python_code_review/blob/main/theorie/02-deserialisation-parsing.md)**

Pickle, `yaml.load`, path traversal, SSRF, SSTI, and XXE.

The reason this gets its own module: the sinks are non-obvious. `yaml.load(data)` looks like a benign config-reading call. `tar.extractall(path)` looks like a simple file operation. `requests.get(url)` looks like standard HTTP. None of them look dangerous until you know what they can do.

SSRF is worth highlighting because the attack surface keeps expanding. Every service that fetches a URL on behalf of the user is a potential SSRF vector: preview generators, webhook receivers, export-to-PDF features, avatar fetchers. In cloud environments, the target is usually the metadata endpoint (169.254.169.254 for AWS, metadata.google.internal for GCP), which leaks IAM credentials. Blocklist defenses are almost always bypassable via IP encoding, IPv6, or DNS rebinding.

Pickle deserialization is the standard vector for ML supply chain attacks: any `.pt`, `.pkl`, or `joblib` file loaded from an untrusted source (a public hub, a user upload) can execute arbitrary code during deserialization via `__reduce__`. The safe alternative is `safetensors`.

**Relevant exercises:** [04-pipeline-config](https://github.com/felixbillieres/python_code_review/blob/main/exercices/04-pipeline-config.py) shows `yaml.load` behind a filter that checks the wrong form of the input. [14-model-registry](https://github.com/felixbillieres/python_code_review/blob/main/exercices/14-model-registry.py) is the ML supply chain exercise - four RCE paths through tar slip, yaml, torch.load, and pickle.loads.

---

### Module 03: Access control and business logic

**[theorie/03-controle-acces-logique.md](https://github.com/felixbillieres/python_code_review/blob/main/theorie/03-controle-acces-logique.md)**

IDOR, mass assignment, missing authentication, ReDoS, open redirect, CORS/CSRF, and framework misconfiguration.

Broken Access Control is OWASP #1 and has been for several years. IDOR is systematically present in APIs that use auto-increment integer IDs - the fix is scoping every query to the current user's ownership, not obscuring the IDs. Mass assignment appears whenever an endpoint accepts arbitrary JSON and passes it directly to an ORM update - fields like `is_admin`, `role`, or `balance` become user-writable.

These issues do not show up in any SAST output. They require understanding the authorization model: who is supposed to own what, and is that enforced at every access point.

**Relevant exercises:** [07-account-api](https://github.com/felixbillieres/python_code_review/blob/main/exercices/07-account-api.py) is pure access control - no injection, just IDOR and mass assignment. [20-team-api](https://github.com/felixbillieres/python_code_review/blob/main/exercices/20-team-api.py) chains mass assignment, IDOR on write, IDOR on read, and ORDER BY injection.

---

### Module 04: Concurrency and Python traps

**[theorie/04-concurrence-pieges-python.md](https://github.com/felixbillieres/python_code_review/blob/main/theorie/04-concurrence-pieges-python.md)**

Async/await bugs, TOCTOU race conditions, mutable default arguments, late-binding closures, exception handling that creates fail-open paths, and supply chain (typosquatting, dependency confusion).

Race conditions in financial APIs are the most impactful variant: two concurrent requests that both pass a balance check then both execute a debit result in a double-spend. The fix is an atomic `UPDATE ... WHERE balance >= amount` rather than a read-then-write.

Async bugs are a different category - they are correctness issues that can become security issues. A missing `await` on a permission check turns it into a no-op that always returns truthy (a coroutine object). A blocking call inside an `async def` handler (e.g., `requests.get` instead of `httpx`) blocks the entire event loop, creating a single-packet DoS.

Supply chain is covered here because it is increasingly a real attack vector: typosquatting on PyPI, dependency confusion in internal package registries, and (more recently) package names hallucinated by LLM code generators that attackers pre-register. `pip-audit` and locked requirements with hash pinning are the defenses.

**Relevant exercises:** [08-wallet-coupon](https://github.com/felixbillieres/python_code_review/blob/main/exercices/08-wallet-coupon.py) has a wallet race condition alongside a second-order injection. [11-async-correctness](https://github.com/felixbillieres/python_code_review/blob/main/exercices/11-async-correctness.py) is entirely about async bugs - the code never actually runs the way you expect.

---

### Module 05: Cryptography, JWT and sessions

**[theorie/05-crypto-jwt-sessions.md](https://github.com/felixbillieres/python_code_review/blob/main/theorie/05-crypto-jwt-sessions.md)**

AES-GCM nonce reuse, padding oracle attacks, JWT algorithm confusion, class pollution, pickle/ML deserialization chains, Flask session forging, and cache poisoning.

JWT issues appear in almost every API. The two most common: (1) `alg=none` - libraries that accept a token with no signature when the header specifies the `none` algorithm; (2) RS256-to-HS256 confusion - a server configured to verify RS256 tokens that reads the algorithm from the token header can be tricked into using the public key (which is public) as an HMAC secret, allowing anyone to forge valid tokens. Both are fixed by the same thing: explicitly specifying the expected algorithm list server-side, never reading it from the token.

Flask session cookies are signed, not encrypted. Decoding them is trivial (base64 decode the first segment). If the `SECRET_KEY` is weak or leaked, they can be forged. `flask-unsign` automates this.

**Relevant exercises:** [06-jwt-download](https://github.com/felixbillieres/python_code_review/blob/main/exercices/06-jwt-download.py) combines a JWT verification issue with a path traversal. [18-model-serving](https://github.com/felixbillieres/python_code_review/blob/main/exercices/18-model-serving.py) has JWT confusion plus six deserialization sinks.

---

### Module 06: Tools and methodology

**[theorie/06-outils-et-methode.md](https://github.com/felixbillieres/python_code_review/blob/main/theorie/06-outils-et-methode.md)**

Bandit, Semgrep, CodeQL, pip-audit, gitleaks, how to structure a finding for a report, and how to integrate SAST into a CI pipeline.

---

## The exercises

The 20 exercises in [exercices/](https://github.com/felixbillieres/python_code_review/tree/main/exercices) cover the full range from quick wins to multi-step chains.

A few worth calling out:

**[14-model-registry.py](https://github.com/felixbillieres/python_code_review/blob/main/exercices/14-model-registry.py)** - ML supply chain. A Flask service that lets users upload and load ML model files. Four separate RCE paths: tar slip, yaml.load, torch.load, and pickle.loads. Realistic because the exact same patterns appear in production ML platforms.

**[17-payment-transfer.py](https://github.com/felixbillieres/python_code_review/blob/main/exercices/17-payment-transfer.py)** - Finance API. IDOR on wallet access, missing rollback on multi-step operations, two TOCTOU race conditions on the balance check, and SQL injection in the audit log. The TOCTOU requires thinking about concurrent requests, not just reading the code linearly.

**[19-rag-agent.py](https://github.com/felixbillieres/python_code_review/blob/main/exercices/19-rag-agent.py)** - LLM indirect injection. A RAG agent that fetches documents from a knowledge base and can send emails via a tool. An attacker who controls a document in the KB can inject instructions that cause the agent to exfiltrate data. The vulnerability is architectural: high-privilege tools in the same context as untrusted content.

**[15-search-api.py](https://github.com/felixbillieres/python_code_review/blob/main/exercices/15-search-api.py)** - Multi-tenant SaaS. MongoDB operator injection via untyped JSON input, cross-tenant IDOR, and ReDoS. The NoSQL injection (`{"$ne": null}` where a username string is expected) bypasses authentication entirely.

**The format that actually worked:** I open the exercise, read the docstring for context, then read the whole file once without taking notes to understand what the service does. Then I enumerate sinks (not reading from line 1), trace backward from the highest-priority ones, and write down all findings before opening the solution. The write-before-you-look rule matters: it is very easy to read a solution and feel like you would have found that. Writing it down first gives an objective record.

The solutions are at [solutions/](https://github.com/felixbillieres/python_code_review/tree/main/solutions). Each one lists every finding from most critical to least, with exploitation steps and a specific fix.

---

## How I actually work through a piece of code

One sentence of threat model verbalization first: "These endpoints take requests from untrusted callers, so every field in the request body, every query parameter, and every path segment is potentially attacker-controlled. I'll start by enumerating sinks."

This matters because "internal users only" and "authenticated users only" are assumptions worth examining before accepting. Most real-world vulnerabilities in authenticated contexts exist because "authenticated" was treated as equivalent to "trusted."

**Step 1: enumerate sinks.** Scan the file for the sink patterns below. Do not start reading from line 1. Build a list of sinks before tracing any of them.

```
SQLi:          cursor.execute(f"..."), db.execute("..." + var), .raw(f"SELECT ...")
Command:       os.system(...), subprocess.Popen(shell=True), subprocess.run(shell=True)
Code exec:     eval(user_input), exec(user_input)
Path:          open(os.path.join(base, user_path)), send_file(user_path)
Deserialize:   pickle.loads(data), yaml.load(data), tarfile.extractall(path), torch.load(f)
SSTI:          render_template_string(f"...{user_input}...")
XXE:           etree.fromstring(xml), etree.parse(f)
Weak crypto:   hashlib.md5(password), random.randint(...) for tokens
```

**Step 2: prioritize.** RCE sinks first (deserialization, command injection, code injection). Then authentication bypasses, then data access issues.

**Step 3: backward trace.** For each sink, in priority order: what is passed to it, where is that assigned, what path does the value travel, is there a sanitizer, and is it the right sanitizer for this specific sink type?

**Step 4: evaluate sanitizers critically.** Is it the right sanitizer for this sink? Applied before or after a transformation that could invalidate it? Is it conditional, with a bypass path? Is it a blocklist?

**Step 5: sort findings by impact.** Critical (RCE, auth bypass, mass data exfiltration). High (authenticated IDOR, stored XSS, significant info disclosure). Medium (reflected XSS with limited impact, weak crypto outside auth). Low (defense-in-depth). An unordered list of findings is less useful than an ordered list with a one-sentence impact statement per finding.

**Step 6: propose concrete fixes.** The specific line and what it should look like, or the structural change if the issue is architectural.

---

## Where SAST fits in

[Semgrep](https://semgrep.dev/), [Bandit](https://bandit.readthedocs.io/), and [CodeQL](https://codeql.github.com/) are useful for catching known-pattern vulnerabilities in recognized forms. They fit at the end of a review, not the beginning - after you have already built your findings list from manual analysis.

What SAST tools do not cover: IDOR, race conditions, broken access control, business logic failures, second-order injection in a general way. Those require understanding the authorization model and the intended application behavior.

[Semgrep's study on IDOR detection](https://semgrep.dev/blog/2025/can-llms-detect-idors-understanding-the-boundaries-of-ai-reasoning/) put numbers on this: Claude Code alone achieved roughly 14% true positive rate on IDOR. A hybrid of Semgrep-as-sink-enumerator followed by targeted analysis achieved 61% precision. Neither replaces a reviewer who understands the authorization model.

The workflow I use: manual backward-taint analysis first, build a findings list independently, then run SAST to catch anything missed, then cross-reference.

Quick reference:

- **Bandit** - Python-specific, fast, covers most sinks, high false-positive rate. Good for CI gates on new code.
- **Semgrep** - rule-based, better precision when tuned to the codebase. Taint mode for inter-function tracing.
- **CodeQL** - dataflow across files and function boundaries, heavier setup, better for propagation across large codebases.
- **[Gitleaks](https://github.com/gitleaks/gitleaks)** - hardcoded secrets in source and git history. Should run on every repository.
- **[pip-audit](https://github.com/pypa/pip-audit)** - dependency CVEs. Run at the start of any audit as a quick pass.

---

## Sources

**Taint analysis**

- [OWASP Source, Sink, and Taint Flows](https://owasp.org/www-community/vulnerabilities/Source_Sink_Flows)
- [CWE/SANS Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html)
- [CodeQL dataflow analysis documentation](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/)
- [Semgrep taint mode](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/)

**Python-specific patterns**

- [Bandit issue list](https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html)
- [PyYAML yaml.load deprecation](https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation)
- [Python subprocess security guide](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [tarfile path traversal CVE-2007-4559](https://nvd.nist.gov/vuln/detail/CVE-2007-4559)
- [Python secrets module](https://docs.python.org/3/library/secrets.html)
- [OWASP Python Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)

**Injection classes**

- [PortSwigger SQLi](https://portswigger.net/web-security/sql-injection)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection)
- [OWASP XXE](https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE))
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)

**Auth, access control, JWT**

- [PortSwigger IDOR](https://portswigger.net/web-security/access-control/idor)
- [PortSwigger JWT attacks](https://portswigger.net/web-security/jwt)
- [PortSwigger JWT algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

**Concurrency**

- [PortSwigger race conditions](https://portswigger.net/web-security/race-conditions)
- [OWASP TOCTOU](https://owasp.org/www-community/vulnerabilities/Time_of_check_time_of_use)
- [Smashing the State Machine (Kettle, 2023)](https://portswigger.net/research/smashing-the-state-machine)

**ReDoS**

- [OWASP ReDoS](https://owasp.org/www-community/attacks/ReDoS)
- [Cloudflare outage postmortem, 2019](https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/)
- [re2 library](https://github.com/google/re2)

**Deserialization**

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [torch.load security advisory](https://pytorch.org/docs/stable/generated/torch.load.html)
- [SafeTensors vs pickle in ML](https://huggingface.co/blog/pickle-safetensors)

**LLM security**

- [OWASP LLM Top 10 (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Simon Willison on prompt injection](https://simonwillison.net/2022/Sep/12/prompt-injection/)
- [PortSwigger web LLM attacks](https://portswigger.net/web-security/llm-attacks)

**SAST and detection**

- [Semgrep vs. Claude on IDOR detection (2025)](https://semgrep.dev/blog/2025/can-llms-detect-idors-understanding-the-boundaries-of-ai-reasoning/)
- [Semgrep AI-powered IDOR detection](https://semgrep.dev/blog/2025/ai-powered-detection-with-semgrep/)

**Practice platforms**

- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [PentesterLab](https://pentesterlab.com/)
- [HackTheBox](https://www.hackthebox.com/)

---

*felix.billieres@ecole2600.com*
