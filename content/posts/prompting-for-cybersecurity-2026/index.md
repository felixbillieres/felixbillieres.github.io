---
title: "Prompting for Security Research: How to Build Prompts That Actually Find Vulnerabilities"
date: 2026-05-07
draft: false
description: "A technical deep-dive into prompting techniques that measurably improve LLM performance in vulnerability research, code auditing, and bug bounty workflows. Covers XML structuring, chain-of-thought verification, multi-stage pipelines, false positive reduction, context engineering, and the exact prompt architecture that produced 500+ zero-days in production codebases."
summary: "Most people use LLMs for security wrong. They ask 'find all bugs' and get noise. This article breaks down the empirical research behind what actually works: structured prompting, adversarial self-verification, CWE-specialized chains, context engineering, and the full composite prompt template that gets you from noise to actionable findings. With numbers."
tags: ["prompting", "llm", "vulnerability-research", "bug-bounty", "claude", "semgrep", "security-research", "ai", "prompt-engineering"]
categories: ["Vulnerability Research", "Bug Bounty", "AI"]
featuredImage: "featured.png"
---

# Prompting for Security Research: How to Build Prompts That Actually Find Vulnerabilities

> This is not a "use AI to hack faster" post. It is a detailed breakdown of what the empirical research says about prompting for security, what Anthropic, Semgrep, Google Project Zero, and academic labs discovered in 2025-2026, and how to translate that into prompts that produce real findings instead of hallucinated noise.

---

## Table of Contents

1. [Why Most Security Prompts Fail](#why-most-security-prompts-fail)
2. [The Numbers That Should Change How You Think](#the-numbers-that-should-change-how-you-think)
3. [Foundation: XML Structure](#foundation-xml-structure)
4. [Chain of Thought and Adversarial Self-Verification](#chain-of-thought-and-adversarial-self-verification)
5. [Persona Engineering That Actually Works](#persona-engineering-that-actually-works)
6. [Few-Shot with Negative Examples](#few-shot-with-negative-examples)
7. [CWE-Specialized Prompting](#cwe-specialized-prompting)
8. [Multi-Stage Pipeline Architecture](#multi-stage-pipeline-architecture)
9. [Context Engineering vs Prompt Engineering](#context-engineering-vs-prompt-engineering)
10. [The Composite Prompt: Maximum-Accuracy Vulnerability Analysis](#the-composite-prompt-maximum-accuracy-vulnerability-analysis)
11. [Bug Bounty Workflows: Context Augmentation and Change Detection](#bug-bounty-workflows-context-augmentation-and-change-detection)
12. [Negative-Days Pattern: Classifying Commits as Security Patches](#negative-days-pattern-classifying-commits-as-security-patches)
13. [Variant Analysis Prompt Chain](#variant-analysis-prompt-chain)
14. [Claude Code Specific Optimizations](#claude-code-specific-optimizations)
15. [The Hybrid Architecture: Why LLM Alone Is Not Enough](#the-hybrid-architecture-why-llm-alone-is-not-enough)
16. [False Positive Reduction Techniques](#false-positive-reduction-techniques)
17. [What Does Not Work](#what-does-not-work)
18. [Sources](#sources)

---

## Why Most Security Prompts Fail

The prompt "find all vulnerabilities in this code" is the worst security prompt you can write. It produces noise, overreports false positives, misses complex chains, and costs you credibility.

The problem is not the LLM. The problem is that this prompt activates the model's sycophantic bias. LLMs are trained on human feedback that rewards "finding things." When you ask an open-ended question about whether there are bugs, the model is biased toward saying yes, even in safe code. This is not an opinion. It is a documented statistical property of RLHF-trained models that multiple research teams have measured and published.

The other failure mode is context. When you paste an entire codebase into a prompt and ask for analysis, reasoning quality degrades visibly after around 3,000 tokens of active analysis. The model starts to pattern-match at the surface level instead of tracing data flows. You get superficial findings that a grep could produce, not the kind of cross-file taint analysis that finds real bugs.

Security prompting is a precision problem. The goal is to maximize true positive rate while minimizing false positives. Every structural decision in your prompt has a measurable effect on that tradeoff.

---

## The Numbers That Should Change How You Think

Before diving into technique, these are the measured results that justify the approach:

**Claude alone on vulnerability detection: 14% true positive rate** (Semgrep, 2025, tested on 800K LOC across 11 applications). Not a useful number for production security work.

**Claude + Semgrep hybrid: 90% better recall and 61% precision on IDOR** versus 22% with Claude alone. Nearly 3x improvement from combining deterministic static analysis with LLM reasoning.

**Think and Verify prompting: +21.24 percentage points** in vulnerability detection accuracy versus baseline, and ambiguous responses cut from 20.3% to 9.1% (VulnSage framework, arxiv 2503.17885).

**CWE-specialized prompting: +18% accuracy** over generic "find vulnerabilities" prompts (arxiv 2408.02329).

**ZeroFalse with flow-sensitive context: F1 of 0.912 on OWASP Java Benchmark, 0.955 on OpenVuln**. Recall and precision above 90% for the best models.

**Sifting the Noise agentic filtering: reduces 92% initial false positive rate to 6.3%** on OWASP Benchmark. On real-world CodeQL alerts, 93.3% FP identification rate.

**Anthropic's Claude Code Security: 500+ high-severity zero-days** in production open-source codebases, including 22 unique vulnerabilities in Firefox in two weeks, finding logic errors that fuzzers running for millions of CPU-hours had not caught.

**Iterative refinement without static feedback: +37.6% increase in critical vulnerabilities** after just 5 naive iterations (IEEE-ISTAS 2025, arxiv 2506.11022). This one is important. LLM self-feedback alone makes security worse, not better.

The takeaway is that prompt structure, pipeline architecture, and tool combination matter more than the choice of model.

---

## Foundation: XML Structure

Claude was trained with XML in its training data. This is not a coincidence you can ignore. XML tags serve as semantic separators that the model processes differently from natural language boundaries.

The practical effect: when you mix instructions with code in a prompt, natural language instructions can be confused with code comments. XML tags eliminate that ambiguity.

The structure for a security analysis prompt:

```xml
<system>
You are a senior application security engineer specializing in web vulnerability research.
Your default posture is skeptical: assume code is secure until proven otherwise.
</system>

<instructions>
Analyze the code below for CWE-89 SQL injection vulnerabilities.
For each finding:
1. Identify the exact source (user-controlled input) with file and line number
2. Trace the full data flow to the sink (SQL execution)
3. Verify whether sanitization or parameterization exists on the path
4. Construct a concrete proof-of-concept input that would trigger exploitation
5. Attempt to DISPROVE the vulnerability before reporting it
</instructions>

<context>
<language>Python</language>
<framework>Django 4.2</framework>
<threat_model>Unauthenticated external attacker via public API</threat_model>
</context>

<code>
{{CODE_BLOCK}}
</code>

<output_format>
Return a JSON array. Each object: cwe_id, title, severity, source_line,
sink_line, data_flow (array of steps), exploit_trigger, false_positive_check,
remediation. If no vulnerabilities found, return empty array with explanation.
</output_format>
```

Why does this work? The model can see exactly where the instructions end, where the context begins, where the code lives, and what format the output should take. There is no guessing. The `false_positive_check` field in the output format is not cosmetic. Forcing the model to complete that field forces it to actually reason about whether the finding is real before outputting it.

Key rules for XML prompting:
- Wrap each content type in its own tag: `<instructions>`, `<context>`, `<code>`, `<examples>`
- Use consistent names and reference them in instructions
- Nest for hierarchical content, never mix hierarchies
- Wrap multiple examples in `<examples>` with individual `<example>` tags

---

## Chain of Thought and Adversarial Self-Verification

Chain of thought is the most misused technique in security prompting. "Think step by step" as a standalone instruction adds marginal value. Structured chain of thought that guides the reasoning path is a different thing.

For vulnerability detection, the relevant insight from VulnSage (arxiv 2503.17885) is that the Think and Verify pattern outperforms everything else at zero-shot. The structure is:

1. **Think**: Trace the code, identify sources and sinks, map the data flow
2. **Verify**: Attempt to disprove each finding you generated in step 1

The disproof step is the critical one. It counteracts sycophantic bias by forcing the model into an adversarial frame where it has to actively look for reasons the vulnerability is NOT real.

This is exactly what Anthropic built into Claude Code Security. Every potential finding goes through an adversarial verification pass where Claude challenges its own results. Only findings that survive this challenge get surfaced. The result was 22 vulnerabilities in Firefox, validated extensively before reporting, with zero hallucinated bugs.

The prompt structure:

```
Analyze this code for authentication bypass vulnerabilities.

STEP 1 - DETECTION:
Identify all code paths where authentication state is checked.
For each path, note: what is being checked, where the check happens,
what data the check relies on.

STEP 2 - ADVERSARIAL VERIFICATION:
For each potential bypass you identified, actively try to disprove it:
- Are there upstream checks that prevent reaching this code path?
- Is there validation I missed that makes the bypass impossible?
- Are there type constraints or value bounds that limit exploitation?
- Could this be a known-safe framework pattern?

If you can disprove a finding, explain why and discard it.
If you cannot disprove it, explain specifically why each disproof attempt fails.

STEP 3 - EXPLOIT CONSTRUCTION:
For findings that survive step 2, write a minimal proof-of-concept.
What specific request, input, or action would trigger the vulnerability?
What is the exact expected behavior?

Rate confidence: HIGH (exploitable with concrete PoC), MEDIUM (likely exploitable,
needs testing), LOW (theoretical, needs more context).
```

The LogiSec approach (LADC 2025) formalizes this as Reductio ad Absurdum, which is worth knowing by name because it describes the same thing precisely:

1. Assume the vulnerability IS exploitable (the assumption)
2. Derive the necessary conditions for exploitation
3. Search the code for evidence that contradicts each condition
4. If any contradiction is found, the vulnerability is a false positive

This mirrors how experienced security researchers actually think. You find something suspicious, then you spend time trying to prove yourself wrong before writing the report.

---

## Persona Engineering That Actually Works

Large-scale studies across 162 personas and 4 model families show that generic personas have a small-to-negative effect on performance for objective tasks. "You are a helpful security assistant" can actually reduce performance compared to no persona at all.

What works is specific, bounded personas with clear expertise domains:

```
You are a senior penetration tester with 12 years of experience in web application
security. Your specialization is authentication and authorization bypass in REST APIs.
You have reported 50+ CVEs, primarily in OAuth and OIDC implementations and RBAC systems.

Your analysis approach:
- You map the attack surface before looking at individual code paths
- You trace data flows from untrusted inputs to sensitive operations
- You distinguish between theoretical and practically exploitable issues
- You cite specific CWE IDs and provide CVSS-like severity ratings
- You are skeptical by default. You assume secure until proven otherwise.
```

The last line matters more than the title. The skeptical posture directly combats the sycophantic bias. A persona that describes the analyst as someone who finds bugs everywhere will find bugs everywhere, including in safe code. A persona that describes the analyst as someone who only reports confirmed exploitable issues filters the output at the source.

What the persona does mechanically: it activates clusters of training data associated with that expertise domain. "Penetration tester" biases the model toward adversarial thinking patterns, attack surface enumeration, and exploit construction. The specificity narrows the distribution of possible responses to the relevant expertise region. The more specific the persona, the tighter the distribution.

---

## Few-Shot with Negative Examples

Few-shot prompting is the single most effective technique according to systematic reviews of LLM code quality research. But most people use it wrong because they only include positive examples (vulnerable code correctly identified as vulnerable).

Without negative examples, models exhibit strong positive bias. They report vulnerabilities in every sample because their few-shot examples only showed them what vulnerable code looks like. You need to show the model what safe code looks like too.

```xml
<examples>

<example>
<code>
@app.route('/profile/<username>')
def profile(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    result = db.execute(query)
    return render_template('profile.html', user=result)
</code>
<analysis>
{
  "findings": [{
    "cwe_id": "CWE-89",
    "title": "SQL Injection via URL parameter",
    "severity": "CRITICAL",
    "source": "username (URL parameter, line 1)",
    "sink": "db.execute(query) (line 3)",
    "data_flow": ["URL param", "f-string interpolation", "raw SQL execution"],
    "exploit_trigger": "GET /profile/' OR '1'='1' --",
    "false_positive_check": "No ORM, no parameterization, raw cursor used. Confirmed TP.",
    "remediation": "db.execute('SELECT * FROM users WHERE username = ?', (username,))"
  }]
}
</analysis>
</example>

<example>
<code>
@app.route('/search')
def search():
    term = request.args.get('q', '')
    sanitized = bleach.clean(term)
    results = Product.query.filter(Product.name.contains(sanitized)).all()
    return jsonify([r.to_dict() for r in results])
</code>
<analysis>
{
  "findings": [],
  "note": "Input sanitized via bleach.clean() before ORM query.
           SQLAlchemy .contains() uses parameterized queries internally.
           No vulnerability present."
}
</analysis>
</example>

</examples>
```

The second example is the one that calibrates the model's threshold. It shows that clean output is expected for safe code, not a list of imaginary issues.

On example selection: research shows two algorithmic approaches outperform random selection. Learn-from-Mistakes (LFM) selects examples the model previously got wrong, forcing correction of systematic weaknesses. Learn-from-Nearest-Neighbors (LFNN) selects examples semantically similar to the query code via k-NN retrieval. Combining both yields the best performance. For Python and JavaScript this matters significantly. For C and C++ the improvement is more limited, likely because of more complex control flow patterns that few-shot examples cannot fully capture.

---

## CWE-Specialized Prompting

The research here is unambiguous. "Find all vulnerabilities" is the worst instruction. "Find CWE-89 vulnerabilities" is 18% more accurate. Multi-class CWE classification outperforms binary vulnerable/not classification. Dataflow analysis prompts improve results for larger models.

The practical structure: one prompt per vulnerability class, with explicit class definition, known patterns for that class, and known safe patterns.

```
You are analyzing code specifically for CWE-79 Cross-Site Scripting vulnerabilities.

VULNERABLE PATTERN:
User-controlled data flows into an HTML rendering context without output encoding.
Example: template renders request.args['name'] directly into HTML.

SAFE PATTERN:
Framework auto-escaping handles output encoding.
Explicit encoding like html.escape() or {{ var | e }} in Jinja2.
Content-Security-Policy prevents execution even if injection occurs.

WHAT TO CHECK:
1. All routes that render templates or return HTML responses
2. Whether user input reaches any of these rendering points
3. Whether auto-escaping is enabled or disabled (check template config)
4. Whether any rendering context uses |safe, mark_safe, Markup(), or similar unsafe flags
5. DOM-based XSS paths: user input into innerHTML, document.write, eval

WHAT TO IGNORE:
- Reflected content in JSON API responses (not an XSS context unless consumed by unsafe code)
- Text nodes with framework auto-escaping confirmed active
- Input already validated to non-HTML character sets

Target code:
{{CODE}}
```

This works because the model now has a precise definition of what counts as a vulnerability in this class, what the safe patterns look like, and what the scope of the analysis is. The "WHAT TO IGNORE" section is as important as the rest. It tells the model exactly what not to report, which directly reduces false positives for that class.

---

## Multi-Stage Pipeline Architecture

The largest source of quality loss in security prompting is trying to do everything in one prompt. Detection, triage, exploit construction, and report drafting are four different cognitive tasks with different objectives. Running them simultaneously produces mediocre output on all four.

The EMNLP 2025 multi-stage approach and Google Big Sleep both demonstrate that sequential, focused stages outperform monolithic prompts. Each stage uses the full attention capacity on a single task. It also enables human review at each checkpoint, which is exactly how professional security audits work.

**Stage 1: Attack Surface Mapping**

```
Map the attack surface of this code. For each user-controlled input:
- Variable name and line number
- Where it enters the application (HTTP param, header, cookie, file upload)
- What validation, if any, is applied immediately on entry
- What the code appears to do with it downstream

Do not assess exploitability yet. Just map inputs.
Output: JSON array of input objects with location, type, and validation status.
```

**Stage 2: Sink Identification**

```
Given these identified inputs: {{STAGE_1_OUTPUT}}

Trace each through the code to security-sensitive operations:
- SQL queries (direct or via ORM)
- OS command execution (subprocess, exec, system)
- File operations (open, write, include)
- HTML/template rendering
- Deserialization (pickle, yaml.load, eval)
- Authentication and authorization checks

For each source-to-sink path, document the transformation steps.
Output: JSON array of source-sink pairs with transformation trace.
```

**Stage 3: Vulnerability Assessment**

```
For each source-sink path: {{STAGE_2_OUTPUT}}

Apply Reductio ad Absurdum:
1. ASSUME the path is exploitable
2. List the necessary conditions for exploitation
3. Check the code for CONTRADICTIONS to each condition
4. If contradiction found: false positive, cite the contradiction
5. If no contradiction: proceed to exploit construction

For surviving findings, construct a minimal concrete PoC.
What exact input triggers the vulnerable behavior?
What is the expected impact?

Output: JSON array of verified findings with confidence rating and PoC.
```

**Stage 4: Synthesis**

```
Compile the verified findings: {{STAGE_3_OUTPUT}}

For each finding:
- Assign CWE ID and severity (CVSS 3.1 estimate)
- Write a clear description suitable for a vulnerability report
- Provide exact remediation with code example
- Note any related findings that share a root cause

Output: Final security report in bug bounty submission format.
```

The key insight is that stage 3 is where false positive reduction happens. By the time you reach synthesis, every finding has survived an adversarial challenge. You are not editing a noisy list. You are formatting confirmed findings.

---

## Context Engineering vs Prompt Engineering

This distinction became prominent in 2025-2026 and it matters practically.

Prompt engineering is what you put inside the context window. Context engineering is how you decide what fills the window in the first place.

The research numbers: 57% of organizations have AI agents in production. 32% cite quality as the top barrier. Most failures trace back to poor context management. Teams that transition to explicit context engineering see a 93% reduction in agent failures and 40-60% cost savings.

For security analysis, context engineering means:

**What to put first**: Static content (system instructions, vulnerability class definitions, few-shot examples, tool definitions). This enables prompt caching, which cuts costs by up to 90% and latency by 85%. The model sees the same instructions every time, cached after the first call.

**What to put last**: Variable content (the code under review, the specific target).

**What to exclude**: Everything not relevant to the current analysis. Do not dump the whole codebase. Use the hierarchical approach:

```
# Step 1: Architecture map (minimal context)
List all files in this project.
Identify authentication modules, API endpoints, database access layers,
and file handling code. Do not read the files yet.

# Step 2: Risk prioritization (based on step 1)
Of the modules identified, rank them by security risk.
Consider: user-facing, handles auth, processes files, executes queries.

# Step 3: Targeted deep dive (load only high-risk code)
Here is the authentication module.
For context, here are the interface definitions from the modules it calls:
<dependencies>{{RELEVANT_INTERFACES}}</dependencies>
Analyze for authentication bypass vulnerabilities.
```

This is exactly how Claude found the Use After Free in Firefox's JavaScript engine. The JS engine was chosen first because it is an independent slice analyzable in isolation. Twenty minutes of architecture exploration before any deep analysis. Then targeted investigation of the identified high-risk surface.

The chunking strategy depends on the vulnerability class:
- XSS and SQLi: function-level analysis is often sufficient
- Auth bypass and IDOR: need cross-file flow analysis
- Race conditions: need full concurrent code paths

---

## The Composite Prompt: Maximum-Accuracy Vulnerability Analysis

This is the full template that combines every technique described above. It is not the prompt you use for quick scans. It is the prompt you use when you need actual findings with minimal false positives.

```xml
<system>
You are a senior application security researcher. Your default posture is skeptical:
assume code is secure until proven otherwise. You only report findings where you can
construct a concrete proof-of-concept. You cite specific file:line for every claim.
You never speculate about code you have not been shown.
</system>

<vulnerability_class>
Target class: CWE-918 Server-Side Request Forgery (SSRF)

Vulnerable pattern: User-controlled input flows into a URL that the server fetches,
allowing an attacker to make the server send requests to internal or unintended hosts.

Safe patterns:
- Allowlist-based URL validation against a fixed list of approved hosts
- No URL constructed from user input at all
- SSRF-specific libraries that enforce allowed origins

Key sinks: requests.get(), urllib.urlopen(), http.get(), fetch() in server context,
curl_exec(), file_get_contents() with URLs, any outbound HTTP call
</vulnerability_class>

<examples>

<example>
<code>
def fetch_profile(user_url):
    response = requests.get(user_url, timeout=5)
    return response.text
</code>
<analysis>
{
  "cwe_id": "CWE-918",
  "title": "SSRF via unvalidated user-supplied URL",
  "severity": "HIGH",
  "source": "user_url parameter",
  "sink": "requests.get(user_url)",
  "data_flow": ["user_url parameter", "direct passthrough", "requests.get()"],
  "exploit_trigger": "user_url=http://169.254.169.254/latest/meta-data/",
  "false_positive_check": "No host validation, no allowlist, no blocklist. TP confirmed.",
  "remediation": "Validate against allowlist: ALLOWED_HOSTS = {'cdn.example.com'}; parsed = urlparse(user_url); assert parsed.netloc in ALLOWED_HOSTS"
}
</analysis>
</example>

<example>
<code>
ALLOWED_ORIGINS = {'cdn.example.com', 'api.example.com'}

def fetch_resource(url):
    parsed = urlparse(url)
    if parsed.netloc not in ALLOWED_ORIGINS:
        raise ValueError("Host not allowed")
    return requests.get(url, timeout=5).text
</code>
<analysis>
{
  "findings": [],
  "note": "Host is validated against an explicit allowlist before the request is made.
           The allowlist uses parsed netloc, not string prefix matching. No SSRF."
}
</analysis>
</example>

</examples>

<instructions>
Analyze the code below for CWE-918 SSRF vulnerabilities using this structured process:

PHASE 1 - SOURCE ENUMERATION:
Identify every location where user-controlled data enters the application.
For each: variable name, file, line number, input source type.

PHASE 2 - SINK ENUMERATION:
Identify every outbound HTTP call, DNS lookup, or resource fetch.
For each: function called, file, line number.

PHASE 3 - TAINT FLOW TRACING:
For each source-to-sink path that exists:
List every transformation step with file:line.
Note any validation, parsing, or sanitization on the path.

PHASE 4 - REDUCTIO AD ABSURDUM:
For each potential vulnerability from phase 3:
1. ASSUME it is exploitable
2. State the necessary conditions (e.g., "user controls the host component of the URL")
3. Search the code for CONTRADICTIONS to each condition
4. If contradiction found: false positive, cite exact code with file:line
5. If no contradiction: proceed to phase 5

PHASE 5 - EXPLOIT CONSTRUCTION:
For findings surviving phase 4:
Construct a minimal PoC. What exact input accesses http://169.254.169.254 or
http://127.0.0.1? What is the specific expected behavior?
Rate confidence HIGH/MEDIUM/LOW with explicit reasoning.

PHASE 6 - INDEPENDENT FP/TP ASSESSMENT:
Evaluate through two independent lenses, do not let one influence the other:
LENS A: All evidence this is a false positive
LENS B: All evidence this is a true positive
</instructions>

<code>
{{TARGET_CODE}}
</code>

<output_format>
JSON array. Each finding: cwe_id, title, severity, confidence,
source (file:line + variable), sink (file:line + function),
data_flow (array of steps with file:line), exploit_trigger,
false_positive_check, lens_a, lens_b, remediation.
Empty array with explanation if no vulnerabilities found.
</output_format>
```

Why this is the right structure:

The XML separation ensures the model never confuses instructions with code. The examples include a negative case that calibrates the detection threshold. The instructions force six distinct reasoning phases, each with a specific objective. Phase 4 is adversarial self-verification. The dual-lens assessment in phase 6 prevents the TP and FP evaluations from contaminating each other (which Semgrep's research identified as a major source of error in single-chain classification). The output format forces a `false_positive_check` field, which means the model has to complete that reasoning before outputting the finding.

---

## Bug Bounty Workflows: Context Augmentation and Change Detection

The bug bounty application of LLMs is different from code audit. You are not usually looking at source code. You are working from recon data, HTTP responses, and JavaScript files.

**Context Augmentation**

The technique is feeding structured external information into the LLM to make it aware of the specific target. Called one of the most underrated techniques of 2025 for bug bounty. The workflow:

1. Run recon: httpx, gau, katana, subfinder
2. Feed outputs into an LLM to identify dynamic endpoints and interesting patterns
3. Summarize the bug bounty policy, sitemap, and recon data into a knowledge file per subdomain
4. Feed the knowledge file at the start of every analysis session

```
You are analyzing a bug bounty target. Here is the current target context:

<target_context>
<program>ExampleCorp VDP on HackerOne</program>
<scope>*.example.com (all subdomains)</scope>
<technology_stack>Node.js backend, React frontend, PostgreSQL, Redis sessions</technology_stack>
<known_endpoints>
  POST /api/v2/users/{id}/preferences
  GET /api/v2/orders/{orderId}
  POST /api/v2/payments/initiate
  GET /api/internal/admin/users
</known_endpoints>
<recon_notes>
  - /api/internal/ prefix returns 401 without auth, 403 with regular auth
  - Order IDs appear to be sequential integers (orderId=12345)
  - User preferences endpoint accepts arbitrary JSON body
</recon_notes>
</target_context>

Based on this context and the endpoints listed, which three endpoints have the highest
probability of IDOR vulnerabilities and why? Be specific about what you would test
and what evidence from the recon data supports each assessment.
```

This is goal-oriented prompting that forces the model to reason about the specific target rather than giving generic advice. The `recon_notes` section is where you put the observations that would normally live in your head. Making them explicit and structured improves the quality of the model's analysis.

**Change Detection Strategy**

New code is buggy code. The single most effective automation project for 2026 in bug bounty is automating detection of new attack surface. When you detect a change, your analysis prompt needs to know what changed:

```
<change_detected>
<target>api.example.com</target>
<change_type>New JavaScript bundle deployed at 14:32 UTC</change_type>
<new_endpoints_discovered>
  /api/v3/documents/share
  /api/v3/documents/export
</new_endpoints_discovered>
<diff_summary>
  New ShareDocument and ExportDocument functions added.
  ExportDocument accepts format parameter and generates files.
  ShareDocument creates shareable links with expiry.
</diff_summary>
</change_detected>

Given this newly deployed functionality, prioritize vulnerability classes to test.
For each class: explain the specific attack vector relevant to this feature,
what request to craft, and what response difference would indicate a finding.
Focus on: SSRF via export URL, path traversal in filename, IDOR via document ID,
and XXE if the export format includes XML parsing.
```

The `diff_summary` section forces you to actually read the new JavaScript before asking the LLM. This is good discipline. The LLM then helps you structure the testing, not replace the thinking.

---

## Negative-Days Pattern: Classifying Commits as Security Patches

Eugene Lim (SpaceRaccoon) built the most elegant application of LLMs in this space: automated detection of security patches before CVE assignment.

The concept: vulnerabilities get patched before CVEs are published. If you monitor commits and detect silent security patches, you can check if your targets use the affected version before the CVE drops. This is called "negative-days" research.

The commit classification prompt:

```
Analyze this git commit diff and determine whether it is patching a security vulnerability.

<commit_metadata>
<repo>{{REPO_NAME}}</repo>
<commit_hash>{{HASH}}</commit_hash>
<commit_message>{{MESSAGE}}</commit_message>
<associated_pr_title>{{PR_TITLE}}</associated_pr_title>
<associated_pr_body>{{PR_BODY}}</associated_pr_body>
</commit_metadata>

<diff>
{{COMMIT_DIFF}}
</diff>

Respond with exactly two parts:

CLASSIFICATION: SECURITY_PATCH or FEATURE_CHANGE or REFACTOR or DEPENDENCY_UPDATE

REASONING: {
  "vulnerability_type": "null or CWE class if SECURITY_PATCH",
  "affected_component": "which component or function was fixed",
  "patch_indicators": ["what in the diff indicates a security fix"],
  "confidence": "HIGH or MEDIUM or LOW",
  "recommended_action": "what to do if target uses this dependency"
}

Security patch indicators to look for:
- Bounds checking added where there was none
- Validation added to previously unvalidated input
- Unsafe function replaced with safe equivalent
- Authorization check added to previously open code path
- Memory management corrections in C/C++
- Removal of hardcoded credentials or secrets
```

Why this format works: the two-part response with the explicit classification forces a binary decision before the reasoning section. This prevents the model from hedging across the entire output. The `patch_indicators` array forces enumeration of specific evidence from the diff, not vague statements about what the code does. The `recommended_action` field makes the output immediately actionable.

The tool chain: GitHub's `listPullRequestsAssociatedWithCommit` API fetches the PR context automatically. The PR title and body are often the most informative part of the context because developers sometimes describe the security implications in the PR description even when the commit message is vague.

---

## Variant Analysis Prompt Chain

Once you find a vulnerability, the question is whether the same pattern exists elsewhere. This is variant analysis. Trail of Bits and Semgrep have both published detailed methodology for this. The LLM application:

**Step 1: Root Cause Extraction**

```
You found a vulnerability in this code: {{ORIGINAL_FINDING}}

Analyze the patch diff to extract the root cause pattern:
<diff>{{PATCH_DIFF}}</diff>

Identify:
1. The exact code pattern that was vulnerable (not just the location)
2. What property made it vulnerable (missing validation, unsafe function, etc.)
3. What would make a similar pattern vulnerable if found elsewhere
4. What a Semgrep rule that matches this pattern would look like

Output the extracted pattern in plain English first, then as a Semgrep YAML rule.
```

**Step 2: Pattern Generalization**

```
Here is the exact-match Semgrep rule for the original vulnerability:
{{EXACT_MATCH_RULE}}

Generalize this rule incrementally to catch variants. For each generalization:
1. What assumption does this relaxation make?
2. What new cases does it match?
3. What is the expected false positive risk of this generalization?

Produce three versions: exact match, moderate generalization, broad search.
Explain the tradeoff at each level.
```

**Step 3: Codebase Scan Guidance**

```
Given these Semgrep rules: {{RULES}}

I am going to scan a codebase for variants. Advise me on:
1. Which paths to exclude (tests, examples, vendor code)
2. What the most likely false positive patterns are for these specific rules
3. How to triage the results to find real variants quickly
4. What secondary verification to apply to each match before reporting
```

This three-step chain turns one bug into a systematic search. The model helps you understand the root cause, abstract it into a rule, and then helps you triage the results of running that rule. Each step is focused. The model is not asked to do everything at once.

---

## Claude Code Specific Optimizations

Claude Code has features that general API usage does not. Using them correctly matters.

**Effort levels**: The `/effort` command controls the thinking budget. For routine scans, `/effort low` is sufficient. For complex authentication chains, race condition analysis, or architecture-level threat modeling, `/effort max` allocates the maximum reasoning budget. The practical impact is most visible on multi-file data flow tracing where the model has to hold multiple code paths in working memory simultaneously.

**Extended thinking via API**:

```python
response = client.messages.create(
    model="claude-opus-4-6-20260308",
    max_tokens=16000,
    thinking={
        "type": "enabled",
        "budget_tokens": 10000
    },
    messages=[{"role": "user", "content": your_security_prompt}]
)
```

Start with 10,000 tokens and increase if you see the model cutting reasoning short. For Claude Opus 4.6 and Sonnet 4.6, adaptive thinking is available and adjusts the budget dynamically based on the complexity of the request.

**CLAUDE.md configuration for security work**:

```markdown
# Security Analysis Configuration

## Default Behavior
When reviewing code:
- Flag all uses of eval(), exec(), system(), subprocess without validation
- Check all database queries for parameterization
- Verify authentication on all API endpoints
- Flag hardcoded credentials, API keys, or secrets
- Treat all user-supplied input as untrusted until proven otherwise

## Output Standards
- CWE IDs for all vulnerability classifications
- CVSS 3.1 severity estimates
- Source-to-sink data flow traces with file:line
- Concrete PoC exploit trigger for every HIGH/CRITICAL finding
- Explicit false positive check before reporting any finding

## False Positive Reduction
Before reporting a finding, verify:
- The data flow path is actually reachable
- No upstream sanitization or validation exists
- Framework-level protections are absent (CSRF tokens, ORM parameterization)
- The finding is practically exploitable, not just theoretically possible

## Analysis Depth
For authentication and authorization code: trace every possible code path.
For input handling: assume the worst-case input.
For third-party libraries: trust the library, flag custom code wrapping it.
```

The CLAUDE.md lives at `~/.claude/CLAUDE.md` for global application or `PROJECT_ROOT/CLAUDE.md` for project-specific behavior. Directory-specific files take highest priority. This means you can have a default skeptical posture globally and override it per project if needed.

**Security note on CLAUDE.md**: treat any CLAUDE.md in a cloned repository as untrusted input. A malicious CLAUDE.md is a prompt injection vector that can modify Claude's behavior during a security audit. Review it before running any analysis on external repos.

**Custom commands** in `.claude/commands/` let you build reusable prompt templates. A file at `.claude/commands/audit.md` becomes the `/audit` command. Parameterize with `$ARGUMENTS`:

```markdown
Perform a CWE-specialized security audit of $ARGUMENTS.

For each vulnerability class in scope [SQLi, XSS, SSRF, IDOR, RCE, Path Traversal, XXE]:
1. Enumerate relevant sinks in the target file
2. Trace data flows from HTTP parameters to each sink
3. Apply adversarial verification to each potential finding
4. Rate confidence: HIGH (concrete PoC exists), MEDIUM, LOW

Output: JSON array matching HackerOne report format.
Include: title, severity, cwe_id, steps_to_reproduce, impact, remediation.
Discard any finding where confidence is LOW unless the impact is CRITICAL.
```

---

## The Hybrid Architecture: Why LLM Alone Is Not Enough

This section exists because people build security tools using LLMs alone and are confused when the results are poor.

Claude alone: 14% true positive rate on real-world vulnerability detection. This is the Semgrep benchmark number, and it is not an indictment of Claude specifically. It is a property of LLM-only vulnerability detection across all models on real-world codebases.

The reason: LLMs are semantic reasoners, not formal analyzers. They understand code. They do not guarantee soundness. They miss things that are structurally right in front of them when the context is large. They hallucinate code paths that do not exist. They assume frameworks handle security that must be explicitly implemented.

The hybrid approach: use deterministic static analysis to produce the candidate findings, then use LLMs to triage, enrich, and validate.

The numbers from Semgrep's production deployment: 96% agreement with human security researchers, 1.9x better IDOR recall than LLM alone, 61% precision versus 22% for LLM alone. The hybrid achieves this because:

1. Semgrep enumerates routes deterministically using AST analysis
2. Semgrep traces taint flows deterministically
3. The LLM evaluates whether those concrete, deterministic findings have mitigating controls in the surrounding context
4. False positive detection and true positive evaluation run as separate prompt chains

The IRIS approach (ICLR 2025) flips this: use the LLM to infer project-specific taint specifications (sources and sinks), then feed those into a traditional static analysis engine. GPT-4 achieves 87.11% recall on sink specification inference. The result is 55 vulnerabilities found on CWE-Bench-Java versus CodeQL's 27, a 103% improvement.

The practical takeaway: integrate Semgrep or CodeQL into your workflow. Use the LLM to write rules, triage findings, and reason about context. Do not use the LLM as a replacement for formal analysis.

---

## False Positive Reduction Techniques

False positives are not a minor annoyance. In bug bounty they kill your reputation. In internal security they waste engineering time. In automated pipelines they cause alert fatigue. These are the techniques with measured reduction numbers.

**ZeroFalse (F1 > 0.91)**: Reconstructs the precise code path between dataflow steps reported by the analyzer, provides CWE-specific context in the prompt, and uses reasoning-oriented LLMs. The prompt receives exactly the evidence required to assess whether an alert is genuine.

```
You are analyzing a potential CWE-89 SQL Injection vulnerability.

STATIC ANALYSIS FINDING:
- Tool: Semgrep rule python.django.security.injection.sql
- Source: request.GET['q'] (api/views.py:42)
- Sink: cursor.execute(query) (api/views.py:45)
- Dataflow steps: request.GET['q'] -> search_term -> f-string query -> cursor.execute

RECONSTRUCTED CODE PATH:
```python
# api/views.py:40-47
def search_products(request):
    search_term = request.GET.get('q', '')
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    with connection.cursor() as cursor:
        cursor.execute(query)
        return JsonResponse({'results': cursor.fetchall()})
```

CWE-89 SPECIFIC CHECK:
Does the data pass through any of these before the sink:
- Parameterized query construction
- ORM methods (Django ORM, SQLAlchemy)
- Escaping functions (escape(), quote())
If yes: likely false positive. If no: confirm source and sink.

TASK: Given ONLY the code path above, determine TP or FP.
Cite specific line numbers. If code context is insufficient, say INSUFFICIENT CONTEXT.
```

**AdaTaint's Counterfactual Validation (43.7% FP reduction)**:

```
For this taint flow: request.GET['id'] -> db.execute(f"SELECT * FROM users WHERE id={id}")

ASSUME this flow is exploitable.

Now check for contradictions:
1. Are there type constraints that make the tainted value unexploitable at the sink?
   Check: is id cast to int() anywhere between source and sink?
2. Do branch conditions on the path guarantee sanitized values?
   Check: is there a conditional that only allows numeric values through?
3. Does control flow make this path unreachable with tainted data?
   Check: is this behind authentication that limits the attacker's access?

If ANY contradiction is found, classify as false positive and cite the contradiction code.
```

**Separate FP/TP evaluation (Semgrep approach)**:

Do not ask the model "is this a true positive or false positive?" in a single question. Run two independent prompt chains:

Chain A: "What evidence in the code suggests this finding is a false positive?"

Chain B: "What evidence in the code confirms this is a real vulnerability?"

Compare the outputs. Do not let the model weight them against each other in a single pass. The sycophancy bias means a single-pass evaluation gets anchored on whichever answer the model finds first.

**The citation requirement (92% accuracy, zero hallucinations)**:

```
For every claim in your analysis, you MUST:
1. Cite the specific file and line number
2. Quote the exact code that supports the claim
3. Do NOT make claims about code you have not been shown
4. Mark any claim without direct code citation as UNVERIFIED

Format: CLAIM [file:line] "exact quoted code" REASONING
```

This sounds mechanical, but it produces a qualitative difference. When the model has to quote the code, it cannot fabricate findings. Fabricated findings do not have quotable evidence. The requirement to cite forces the model to only report what actually exists in the code it was given.

---

## What Does Not Work

These are documented failures. Knowing them saves time.

**"Find all vulnerabilities"**: Massive noise. The model reports something in almost every sample because the prompt activates positive reporting bias. Use CWE-specialized prompts.

**Single-shot on large codebases**: Quality degrades past around 3,000 tokens of active analysis. Use hierarchical chunking and multi-stage pipelines.

**LLM alone without static analysis**: 14% TPR. Not a useful number. Combine with Semgrep or CodeQL.

**Generic personas**: "You are a helpful security assistant" has small-to-negative effect. Use specific, expertise-bounded personas with skeptical posture.

**Trusting without verification**: LLMs hallucinate plausible but wrong vulnerability descriptions. Always verify with static analysis or manual review before submission.

**Iterative refinement without static feedback**: This one causes active harm. Five naive iterations increase critical vulnerabilities by 37.6%. If you are using LLM self-feedback to refine security code or findings, you are making the output worse. Use external validation (static analyzer, human review) between iterations.

**Business logic vulnerabilities**: LLMs do not have the domain context to reason about business logic flaws. They cannot tell you that a discount coupon should not stack with a refund, or that a user should not be able to modify another user's subscription tier, because they do not know the business rules. Provide those rules explicitly in the prompt or skip the class entirely.

**Submitting raw LLM output to bug bounty programs**: As of mid-2025, approximately 20% of bug bounty submissions were AI-generated noise. Programs noticed. HackerOne updated its AI policy in February 2026. Bugcrowd explicitly rejects "automated or unverified outputs." Use AI as a research assistant. Validate manually. Write the report yourself.

**Prefilling with Claude 4.6+**: Prefilling the assistant turn to force output format returns a 400 error in Claude 4.6 models. Use explicit format instructions in the prompt or tool use instead.

---

## Sources

**Empirical Research**

- VulnSage: Reasoning with LLMs for Zero-Shot Vulnerability Detection: https://arxiv.org/html/2503.17885v1
- ZeroFalse: CWE-Specialized FP Reduction (F1 0.912): https://arxiv.org/abs/2510.02534
- IRIS: Neuro-Symbolic Taint Specs (ICLR 2025, +103% vs CodeQL): https://arxiv.org/abs/2405.17238
- AdaTaint: Counterfactual Validation (43.7% FP reduction): https://arxiv.org/abs/2511.04023
- LogiSec: Reductio Ad Absurdum (LADC 2025): https://link.springer.com/chapter/10.1007/978-3-032-11539-3_7
- LLMxCPG: Code Property Graph (USENIX Security 2025, 15-40% F1 gain): https://arxiv.org/abs/2507.16585
- Sifting the Noise: Agentic FP Filtering (92% to 6.3% FPR): https://arxiv.org/abs/2601.22952
- FDSP: Iterative + Static Feedback (40.2% to 7.4% vuln rate): https://www.mdpi.com/2624-800X/5/4/110
- Security Degradation in Iterative LLM Refinement (IEEE-ISTAS 2025): https://arxiv.org/html/2506.11022
- CWE-Specialized Prompting (+18% accuracy): https://arxiv.org/abs/2408.02329
- Sequential Multi-Stage Approach (EMNLP 2025): https://aclanthology.org/2025.emnlp-main.1071.pdf
- Benchmarking Prompt Engineering for Secure Code: https://arxiv.org/abs/2502.06039
- Citation-Grounded Code Comprehension (92% accuracy, zero hallucinations): https://arxiv.org/abs/2512.12117
- Persona Effect Studies: https://arxiv.org/html/2311.10054v3

**Production Systems**

- Anthropic Claude Code Security (500+ zero-days): https://www.anthropic.com/news/claude-code-security
- Anthropic Red Team Zero-Days Blog: https://red.anthropic.com/2026/zero-days/
- Mozilla + Anthropic Firefox Audit (22 vulns, 2 weeks): https://blog.mozilla.org/en/firefox/hardening-firefox-anthropic-red-team/
- TechCrunch Firefox coverage: https://techcrunch.com/2026/03/06/anthropics-claude-found-22-vulnerabilities-in-firefox-over-two-weeks/
- Semgrep Hybrid AI Architecture (96% agreement): https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/
- Semgrep IDOR Detection Study: https://semgrep.dev/blog/2025/can-llms-detect-idors-understanding-the-boundaries-of-ai-reasoning/
- Semgrep AI-Powered Detection: https://semgrep.dev/blog/2025/ai-powered-detection-with-semgrep/
- Google Big Sleep SQLite Zero-Day: https://projectzero.google/2024/10/from-naptime-to-big-sleep.html
- XBOW Architecture (#1 HackerOne): https://xbow.com/blog/top-1-how-xbow-did-it
- CAI Framework (3600x faster on CTF tasks): https://github.com/aliasrobotics/cai
- RAPTOR (Claude Code security agent): https://github.com/gadievron/raptor

**Techniques and Tooling**

- SpaceRaccoon Negative-Days Methodology: https://spaceraccoon.dev/discovering-negative-days-llm-workflows/
- Semgrep Variant Analysis: https://semgrep.dev/blog/2025/finding-more-zero-days-through-variant-analysis/
- Trail of Bits Skills for Claude Code: https://github.com/trailofbits/skills
- Transilience Community Tools: https://github.com/transilienceai/communitytools
- Datadog LLM False Positive Filtering: https://www.datadoghq.com/blog/using-llms-to-filter-out-false-positives/
- AWS Security Agent Multi-Agent Architecture: https://aws.amazon.com/blogs/security/inside-aws-security-agent-a-multi-agent-architecture-for-automated-penetration-testing/

**Anthropic Documentation**

- XML Tags: https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/use-xml-tags
- Extended Thinking: https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/extended-thinking-tips
- Adaptive Thinking: https://platform.claude.com/docs/en/build-with-claude/adaptive-thinking
- Claude 4 Best Practices: https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/claude-4-best-practices
- Claude Code Best Practices: https://www.anthropic.com/engineering/claude-code-best-practices
- Prompt Caching: https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching

**Bug Bounty Context**

- HackerOne AI Security Trends 2025: https://www.hackerone.com/blog/ai-security-trends-2025
- HackerOne AI Policy Update: https://www.theregister.com/2026/02/18/hackerone_ai_policy/
- Bugcrowd AI Triage: https://www.bugcrowd.com/blog/bugcrowd-ai-triage-speeds-vulnerability-resolution-elevates-hacker-experience/
- Context Augmentation for Bug Bounty: https://infosecwriteups.com/utilising-context-augmentation-in-llms-for-bug-bounty-c41a0c03f4b8
- LLM Recon Workflows: https://bitpanic.medium.com/how-i-use-llms-to-supercharge-my-bug-bounty-recon-3f9892c6b5a0
- Context Engineering vs Prompt Engineering: https://neo4j.com/blog/agentic-ai/context-engineering-vs-prompt-engineering/
