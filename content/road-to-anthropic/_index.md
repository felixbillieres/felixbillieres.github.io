---
title: "Road to Anthropic"
description: "A collection of projects and learnings in AI security, ML and offensive security research"
---

I've been closely following Anthropic's work on AI safety and security — their research on red teaming, model vulnerabilities, and initiatives like the Fellows program genuinely resonate with what I care about in offensive security.

When the time comes for me to look for a full-time position, applying there is something I'd really like to do. In the meantime, this section serves as a personal log of everything I build, learn and explore at the intersection of AI and security — a running record of hands-on experience I can point back to.

---

## MCP Security Research

A series of vulnerability research articles on the Model Context Protocol (MCP) — protocol-level gaps, SDK implementation bugs, and the attack surface that comes with plugging AI assistants into external tools.

### [MCP SVG Icon Injection: From XSS to RCE Through the Protocol Spec](/posts/mcp-svg-icon-xss-to-rce/)

The MCP spec allows `data:image/svg+xml` icons and only optionally recommends sanitizing them. A malicious server can embed JavaScript in an `<animate onbegin>` handler inside a normal-looking SVG icon. When a client renders it via `innerHTML`, the script executes silently on connection — no user interaction required. In an Electron client with `nodeIntegration: true`, this escalates to full RCE. Reported to Anthropic VDP, closed as Informative.

### [MCP SSRF via OAuth PRM Discovery: How a 401 Turns Your Client Into a Proxy](/posts/mcp-ssrf-oauth-prm-discovery/)

A malicious MCP server returns a `401` with a crafted `WWW-Authenticate` header pointing `resource_metadata` at any internal URL it wants. The MCP SDK fetches that URL without origin validation — blind SSRF, one header, zero interaction beyond connecting to the server. Both Python and TypeScript SDKs affected, including Claude Desktop and Claude Code. Reported to Anthropic VDP, closed as duplicate.
