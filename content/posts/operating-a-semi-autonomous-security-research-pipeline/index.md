---
title: "Operating a Semi-Autonomous Security Research Pipeline Without Turning It Into a Scanner"
date: 2026-10-05
draft: false
description: "An AI-assisted security research pipeline with durable leads, quota-aware pacing, scoped tools, evidence-first handoffs, low-noise operations and human approval."
summary: "How one control plane preserves leads and evidence, paces provider capacity, routes second opinions and keeps operator updates useful."
featuredImage: "featured.png"
images: ["featured.png"]
tags: ["agentic", "ai", "bug-bounty", "vulnerability-research", "security-automation", "context-engineering", "mcp", "llm", "architecture"]
categories: ["AI", "Vulnerability Research", "Bug Bounty"]
---

# Running a Long-Lived Security Research Pipeline

AI-assisted bug bounty can produce duplicate traffic, convincing false positives, lost context and reports that are not ready to send. I built the surrounding system to keep those failure modes visible.

The model is one worker in that system. Scope, state, evidence, scheduling and approval sit outside the model, in components that can be inspected and changed independently.

This post covers the operational architecture I use for long-running, authorised research. It does not include target data, credentials, commands, provider configuration, request recipes, payloads or deployment details.

> The point of the pipeline is to preserve judgement under uncertainty, not to generate more requests.

## Why I built it

I did not set out to build a “hacking bot”. I was curious about a more mundane and, to me, more interesting question: what would it take to build a clean, scalable and robust research companion that could keep useful work moving almost 24/7 without turning my own backlog into noise?

“Almost 24/7” does not mean unlimited testing. It means the boring but valuable work can continue between my focused sessions: sorting evidence, preserving a negative result, checking a source-backed assumption, preparing a bounded question, or surfacing a dependency that needs a human decision. Anything target-facing remains authorised, constrained and accountable.

Part of the inspiration came from researchers who make the reasoning visible rather than presenting automation as magic. Cassim Khouani, aka [Aituglo](https://aituglo.com/), and his [YesWeHack interview](https://www.yeswehack.com/community/llms-bug-bounty-interview-aituglo) were useful prompts to think seriously about LLM-assisted bug bounty. ProjectDiscovery’s [behavioural audit of offensive-security LLM runs](https://projectdiscovery.io/blog/watching-agents-work-a-behavioral-audit-of-offensive-security-llm-runs) was the equally important counterweight: inspect what an agent actually does, not what it claims to be doing.

The design follows a critical-thinking rule: a promising idea needs a mechanism, a control, evidence and a credible way to be wrong.

## Cost and capacity

Scalability is not just throughput. It is also knowing where expensive reasoning earns its place. A system that sends its most capable model to every small question eventually becomes a costly way to produce very polished uncertainty.

The pipeline routes work by the quality of the question rather than treating every session equally:

- inexpensive capacity handles mapping, source collection, classification and first-pass evidence organisation;
- deeper reasoning is reserved for a credible primitive, difficult refutation, source-heavy continuation, or a decision with real safety consequences;
- a second provider is most useful as a fresh reviewer or hand-off, given structured facts rather than a transcript it is likely to inherit and agree with;
- human attention is reserved for scope, risk and reportability decisions. It should not be spent reviewing agent theatre.

| Cost tier | Assigned work | Why it belongs there |
|---|---|---|
| Low | organisation, retrieval, normalisation, routine evidence bookkeeping | These tasks benefit from consistency and volume more than novel reasoning. |
| Medium | bounded hypothesis research and first-pass source analysis | Enough room to reason, while a negative result remains cheap to record. |
| High | hard continuation, adversarial refutation and safety-sensitive judgement | The extra cost is justified only when prior evidence creates a real decision to make. |
| Human | scope changes, elevated-risk testing and report submission | Authority and accountability cannot be bought as model tokens. |

The exact vendors and prices are deliberately not the point: both change faster than the architecture. The durable rule is to attach a budget to the question, preserve the usage record, and stop spending when the evidence yield drops.

That is also why I avoid a huge swarm of agents. More parallel sessions can mean more correlated mistakes, more duplicate work and more unreviewable output. The coordinator receives a *ceiling* on sessions, not a target it must fill. The goal is to spend generously on evidence and stingily on speculation.

## Provider and model selection

The pipeline uses more than one provider, but it does not pick one once and let that choice leak indefinitely into every child session. A provider and a reasoning tier are selected when a session starts; the decision is recorded with the investigation so I can later answer a mundane but essential question: *which quota produced this work?*

The default coordinator is on Codex. A cycle reads its observed weekly quota before planning and sets a ceiling of one to three sequential sessions. When consumption is well ahead of elapsed time, the continuous loop waits between cycles; when behind, it can use more slots. The operational aim is to approach the end of the weekly window with most of the Codex allowance used, not exhaust it several days early. An absent or expired quota observation means a conservative cadence, not an imaginary fresh allowance. None of this guarantees that enough worthwhile leads will exist to use the whole window.

Claude is also my personal subscription. Automatic Claude use requires both an off-hours window and fresh readings below locally chosen headroom thresholds for its short and weekly windows. At the time of writing, the autonomous threshold is 70% used for each. These are *my reserve settings*, not provider limits or a claim about either model's capability. A deliberate operator window can override the automatic reserve. It can pin Codex, pin Claude, or allow both on one programme until a stated end time; that choice covers the coordinator and workers. It does not override the programme's scope, traffic constraints or the providers' actual limits.

This is not a claim that one model is universally better. It is capacity planning around two subscriptions and one human operator. It preserves an interactive Claude reserve while letting Codex carry most of the autonomous load. The control plane distinguishes that *weekly allowance* from a session's *context window*: the former governs launch cadence; the latter governs which relevant facts should be placed in the prompt. Automatic per-session context compaction is not yet part of this implementation.

Within the selected provider, the model tier follows the task: lightweight work for organisation and mapping, a standard tier for a bounded investigation, and deep reasoning only for hard source analysis, continuation or adversarial refutation. A pacing rule can step work down when a provider’s allowance is being consumed faster than its window elapses. Escalation goes the other way only after the cheaper session leaves a precise unresolved question.

The hand-off contains a compact factual brief: what was observed, what was ruled out, the remaining question and the proof standard. It does not carry a transcript that nudges the next model to agree with the first one.

{{< mermaid >}}
%%{init: {'theme':'base','themeVariables':{'background':'#ffffff','fontSize':'15px','primaryColor':'#dbeafe','primaryTextColor':'#0f172a','primaryBorderColor':'#1e40af','lineColor':'#334155','textColor':'#0f172a'}}}%%
flowchart TD
    O{Explicit operator window?}
    O -->|yes| M[Pin target and provider choice<br/>across coordinator and workers]
    O -->|no| Q[Read observed Codex weekly usage<br/>and time to reset]
    Q --> C[Set cycle ceiling: 1 to 3 sessions<br/>plus inter-cycle pacing]
    C --> P[Codex coordinator writes a plan]
    M --> P2[Coordinator on selected provider]
    P --> D{Evidence-backed dispatch?}
    P2 --> D
    D -->|no| N[Record why no session starts]
    D -->|yes| T{Task depth}
    T -->|first pass| L[Light or standard model]
    T -->|qualified continuation| H[Deeper model]
    L --> R{Provider eligible now?}
    H --> R
    R -->|yes| S[Start one bounded investigation]
    R -->|no| W[Wait, or retain the lead for later]
    S --> E[Record provider, evidence and outcome]
{{< /mermaid >}}

The planner chooses *questions*; the launch policy enforces *capacity*. A manual choice wins over automatic pacing, while the deterministic scope and human-reporting gates remain in force either way.

## Requirements

The pipeline has to satisfy four properties that pull in different directions:

1. **Depth:** it should keep working a promising hypothesis across many short contexts.
2. **Restraint:** it must not turn “try harder” into repeated traffic, brute force, or unsafe state changes.
3. **Memory:** it must retain why something was disproven, not only that it was tried.
4. **Accountability:** reports and externally consequential actions remain human decisions.

That last property matters more than it sounds. A security researcher can make a judgement call from years of experience. A model can make a convincing argument. Neither is a substitute for a durable record of scope, evidence, controls, and approval.

Google Project Zero’s Naptime work is a useful mental model here: the agent is not a replacement for a researcher; it is an agent paired with a target-specific environment, tools, and evaluation loop. [Naptime](https://projectzero.google/2024/06/project-naptime.html) makes the same broader point from a vulnerability-research perspective. The harness shapes what the model can actually accomplish.

## System overview

{{< mermaid >}}
%%{init: {'theme':'base','themeVariables':{'background':'#ffffff','fontSize':'15px','primaryColor':'#dbeafe','primaryTextColor':'#0f172a','primaryBorderColor':'#1e40af','lineColor':'#334155','textColor':'#0f172a'}}}%%
flowchart TB
    H[Human operator<br/>scope · priorities · final submission]
    P[Programme policies and<br/>positive scope lists]
    Q[Provider quota observations<br/>and operator window]
    S[(Durable control plane<br/>memory · leads · plans · findings · outbox)]
    C[Coordinator<br/>rank discriminating questions]
    R[Research session<br/>one bounded hypothesis]
    E[Evidence store<br/>raw artifacts and pointers]
    V[Refutation and policy triage]
    D[Discord signal surface<br/>alerts · digest · review]

    P --> S
    Q --> C
    H <--> S
    S --> C
    C --> R
    R --> E
    E --> S
    R --> V
    V --> S
    S --> D
    D --> H
{{< /mermaid >}}

The diagram is deliberately boring. That is a compliment. The durable control plane is the centre; models are workers around it. Discord or another chat surface is an interface to the state, not the state itself. A transcript is diagnostic material, not the canonical record.

## Database and durable state

The control plane is a small SQLite database in WAL mode. SQLite is the right trade for a single-machine, low-write-concurrency system: no separate database service to operate, atomic state transitions, a backup that is a single durable artifact, and enough structure to reject an agent’s vague recollection in favour of a record. Moving to a networked database would make sense only when the system becomes genuinely multi-machine.

It is not one giant “agent memory” blob. The data is separated by the question it needs to answer:

| Record family | Stored form | What it answers later |
|---|---|---|
| Programme policy and scope | Normalised assets and constraints, original rules, provenance and change fingerprints | Is this action allowed under the policy that applied at the time? |
| Observations | Typed facts: programme, asset, kind, value, source, confidence and first/last-seen timestamps | What do we know exists? |
| Attempts | Surface, technique, parameter fingerprint plus readable structured parameters, outcome, closing property, evidence reference and policy/scope snapshot | Was this exact question already settled, and why? |
| Open gaps and lessons | Typed dependency or reusable rule, scoped to a programme, a technology, a vulnerability class or globally | What is blocked, and what knowledge transfers safely? |
| Investigations and usage | One row per session with provider, usage accounting, evidence yield and stop reason | What ran, what did it consume, and did it learn anything? |
| Investigation leads | Hypothesis, surface, state, evidence pointer, next discriminating test or reopening condition | Which promising question deserves continuation rather than being mistaken for a finding or discarded as a negative? |
| Findings and decisions | Finite state, evidence pointer, scope/duplicate gates, plus an append-only audit decision log | Who approved a consequential transition, and when? |
| Outbox | A durable message, severity, routing metadata and delivery timestamp | Was an operator update generated and actually delivered? |

Some fields are relational by design; a small amount of structured JSON is retained where the original shape matters, such as a task payload or the parameters used for an attempt. That distinction matters. A fingerprint lets the system avoid replaying the same experiment; the readable structured record lets a human or a refuter understand what was actually attempted.

Lessons are invalidated rather than silently overwritten. Scope changes are versioned rather than retroactively rewriting history. The result is not just memory for agents: it is a lightweight ledger of how a conclusion was reached.

{{< mermaid >}}
%%{init: {'theme':'base','themeVariables':{'background':'#ffffff','fontSize':'15px','primaryColor':'#dbeafe','primaryTextColor':'#0f172a','primaryBorderColor':'#1e40af','lineColor':'#334155','textColor':'#0f172a'}}}%%
flowchart LR
    Policy[Policy and scope<br/>rules · constraints · versions]
    Memory[Research memory<br/>observations · attempts · gaps · lessons]
    Leads[Lead ledger<br/>hypothesis · evidence · next test]
    Work[Investigation ledger<br/>plan · provider · usage · stop reason]
    Review[Finding lifecycle<br/>candidate · review · approval]
    Audit[Audit and delivery<br/>decisions · tasks · outbox]

    Policy --> Work
    Memory --> Work
    Work --> Memory
    Work <--> Leads
    Work --> Review
    Review --> Audit
    Audit --> Work
{{< /mermaid >}}

## Research cycles

The pipeline runs in discrete cycles. Each cycle re-reads durable state, writes a plan, executes at most its capacity ceiling, records outcomes, and stops. A session is bounded by its *question and evidence contract*; it is not necessarily a short wall-clock call. The next cycle starts from recorded facts rather than the previous model’s increasingly long conversation.

{{< mermaid >}}
%%{init: {'theme':'base','themeVariables':{'background':'#ffffff','fontSize':'15px','primaryColor':'#dbeafe','primaryTextColor':'#0f172a','primaryBorderColor':'#1e40af','lineColor':'#334155','textColor':'#0f172a'}}}%%
flowchart TD
    A[Policies and scope] --> C[Coordinator]
    B[Memory and prior evidence] --> C
    C --> D[Written plan]
    D --> E{Executable and in scope?}
    E -- no --> F[Record why it is blocked]
    E -- yes --> G[One bounded session]
    G --> H[Evidence + structured outcome]
    H --> I{What did the evidence establish?}
    I -- negative --> J[Store closing property]
    I -- unresolved but testable --> U[Save lead, evidence and next test]
    I -- dependency missing --> Z[Pause lead with reopening condition]
    I -- impact observed --> K[Independent refutation]
    K --> L{Survives?}
    L -- no --> J
    L -- yes --> M[Policy and report triage]
    M --> N[Human review queue]
    N --> B
    J --> B
    U --> B
    Z --> B
    F --> B
{{< /mermaid >}}

This shape solves a surprisingly common agent problem: a session that fails halfway through should not become a hidden dead end. It should leave a useful object behind: *blocked because an owned account is missing*, *inconclusive because the authoritative source package is unavailable*, or *not vulnerable because the permission check happens before the handler*. Those are three radically different things, and the next session needs to know which one occurred.

Anthropic’s guidance on [effective harnesses for long-running agents](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents) reaches a similar conclusion in a different domain: durable artifacts and incremental work are more reliable than asking one context window to remember an entire project.

## One question per session

“Investigate the application” is not an executable task. A session needs a question that can be settled either way.

Good examples are deliberately narrow:

- Does this documented callback require the same capability on every dispatch path?
- Can two researcher-owned accounts demonstrate a cross-account transition?
- Does an exact source version contain a path from an untrusted field to a sensitive sink?
- Does a supposedly public route return a protected resource when compared with a clean control?

Every session gets a stopping condition before it can touch the target. For example: *stop if source shows all candidate handlers are capability-gated; otherwise send at most a few non-mutating, source-backed controls*. This is not bureaucracy. It prevents a model from replacing uncertainty with enumeration.

The output is a structured result, not free-form optimism:

| Field | Why it exists |
|---|---|
| Outcome | Distinguishes a proof, a negative, an unresolved question and an operational error. |
| Confidence | Forces a statement about the quality of evidence, not the model’s confidence in its writing. |
| Impact | Prevents “interesting behaviour” from becoming a finding without a victim or security transition. |
| Evidence location | Lets a later reviewer see what was actually observed. |
| Next action | Turns an inconclusive result into a dependency rather than a rediscovery. |
| Refuter / triage status | Makes missing independent review visible. |

If the session fails to write a valid outcome artifact, the control plane considers it failed even when the transcript looks brilliant. This sounds harsh, but it is the right failure mode: without durable evidence, a later agent cannot distinguish an excellent investigation from a hallucinated one.

## Research memory

The pipeline does not treat all history as one retrieval corpus. It uses four kinds of memory, because each answers a different question.

{{< mermaid >}}
%%{init: {'theme':'base','themeVariables':{'background':'#ffffff','fontSize':'15px','primaryColor':'#dbeafe','primaryTextColor':'#0f172a','primaryBorderColor':'#1e40af','lineColor':'#334155','textColor':'#0f172a'}}}%%
mindmap
  root((Research memory))
    Observations
      technology fingerprints
      routes and assets
      policy facts
    Attempts
      exact surface
      method used
      observed result
    Open gaps
      missing input
      re-opener
      blocked dependency
    Lessons
      programme
      vulnerability class
      technology
      global methodology
{{< /mermaid >}}

An **observation** might say that a target uses a particular framework. An **attempt** says which exact route and mechanism were measured. An **open gap** says what is currently impossible and what would reopen it. A **lesson** captures reusable reasoning, such as a reliable anti-false-positive control for a vulnerability class.

The most valuable field in a negative result is the *closing property*. “LFI tested: no issue” is nearly worthless. “The exact source has no attacker-controlled data flow to a filesystem read, include, write or evaluation sink; direct entry is guarded before the handler” prevents the next person from spending the same hour again.

This is also why a generic pile of “similar CVEs” does not help much. It is retrieval without a decision boundary. A useful memory entry is tied to a surface, a mechanism, an evidence standard, and a reason to reopen it.

## A lead is a first-class result

A useful lead is neither a reportable finding nor a failed experiment. It is a hypothesis with an evidence pointer and a next observation that could discriminate between competing explanations. Earlier versions of the pipeline could leave such work buried in an `inconclusive` note. A separate lead ledger now makes it visible to the next coordinator and to me, without inflating the finding queue.

{{< mermaid >}}
%%{init: {'theme':'base','themeVariables':{'background':'#ffffff','fontSize':'15px','primaryColor':'#dbeafe','primaryTextColor':'#0f172a','primaryBorderColor':'#1e40af','lineColor':'#334155','textColor':'#0f172a'}}}%%
stateDiagram-v2
    [*] --> Active: hypothesis + next test
    Active --> Paused: missing prerequisite
    Paused --> Active: reopening condition met
    Active --> Escalated: precise second-opinion request queued
    Escalated --> Active: answer changes the next test
    Active --> Validated: primitive independently supported
    Active --> Closed: discriminating test refutes it
    Paused --> Closed: evidence rules it out
    Validated --> [*]: separate finding review
    Closed --> [*]
{{< /mermaid >}}

These are conceptual paths, not a claim that every transition is automated today. In particular, `escalated` records a queued request; it does **not** mean a second provider is running, and its answer is not yet automatically reconciled back into the lead. A queued question is deduplicated by its investigation cell, and revisions preserve the earlier question. A lead without a next test is paused with a reopening condition rather than repeatedly redispatched. A validated primitive still has to pass the separate finding and human-review process.

This is where cross-provider work can be valuable: a stronger or simply different model receives the observation, the benign alternative, the exact unresolved question and the minimum proof standard. It should not inherit a long persuasive transcript. I have not yet claimed an automatic improvement in finding yield; that needs replayable evaluation cases, including promising leads that never become reports.

## Skills

Skills are not a collection of magic prompts. They are reusable operating procedures with a narrow responsibility. The useful pattern is a small set of skills, invoked at specific points in the investigation:

| Moment | Skill responsibility | What it prevents |
|---|---|---|
| Before the first meaningful request | Source and mechanism research | Sending generic payloads that only measure a WAF. |
| Once a vulnerability class is credible | Class-specific proof checklist | Reporting an observation that lacks impact. |
| Once a candidate exists | Independent refutation | Confirmation bias and self-validated claims. |
| Before the human review queue | Scope/policy/report triage | Duplicate, out-of-scope or non-qualifying reports. |
| After a result | Memory recording | Repeating a solved or blocked branch. |

The ordering is the important part. A report-writing skill should not become a hunting skill. A triage skill should not invent missing measurements. A researcher should not blindly execute target-facing actions just because it found a famous CVE.

I prefer source-first work for the same reason I prefer narrow sessions. Default payloads are the corpus that WAF rules and every other researcher already know. A source-backed hypothesis can be small enough to be meaningful: one parameter, one code path, one control. It produces less traffic and better evidence.

## Tools and permissions

The tools available to an agent are divided by what they can change:

- **Read-only research:** source code, public documentation, local evidence and passive inspection.
- **Target interaction:** only when a programme context, scope decision, required user-agent and rate constraints exist.
- **Owned-account operations:** a dedicated path for test accounts and verification, with account metadata recorded for later sessions.
- **Operator communication:** an append-only outbox rather than a direct “submit report” API.

Browser automation is useful, but it is not special. It must pass through the same scope and policy assumptions as a command-line client. The same goes for new MCP servers: adding a tool is adding a new transport and a new authority boundary, not just adding functionality.

The [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) is worth reading here. Its advice to validate tool output, separate tool data from instructions, use least privilege, and require human approval for sensitive actions translates directly to research agents. MCP is an integration protocol, not a security boundary by itself.

## Scope enforcement

Security programmes are not homogeneous. Scope can contain domains, wildcards, app identifiers, exclusions, path-specific rules, a mandatory user-agent, rate guidance, VPN requirements, and testing prohibitions. Natural-language instructions are not a robust place to hold all of that.

The pipeline therefore keeps a normalised scope store and makes scope decisions deterministic:

1. explicit exclusions win;
2. the most specific matching inclusion supplies the active constraints;
3. ambiguity goes to review;
4. no matching inclusion means deny.

But there is an important engineering distinction: **a good scope matcher is not enough unless every target-facing path invokes it**.

That includes shell commands, browsers, helper scripts, and any future integration. A policy in a prompt is advice. A policy check in one tool wrapper is partial coverage. The design goal is a fail-closed gate at every network-capable boundary, backed by regression tests whenever a new tool is introduced.

This is not merely a security concern. It is a reliability concern. If one browser transport silently escapes the same constraints as the rest of the system, the pipeline’s audit trail becomes incomplete exactly when it matters most.

{{< mermaid >}}
%%{init: {'theme':'base','themeVariables':{'background':'#ffffff','fontSize':'15px','primaryColor':'#dbeafe','primaryTextColor':'#0f172a','primaryBorderColor':'#1e40af','lineColor':'#334155','textColor':'#0f172a'}}}%%
flowchart LR
    H[Hypothesis] --> P{Active programme?}
    P -->|no| X[Stop and request review]
    P -->|yes| I{Explicitly in scope?}
    I -->|no or ambiguous| X
    I -->|yes| C[Apply policy constraints<br/>rate · method · account · risk]
    C --> E{Evidence-backed and non-mutating?}
    E -->|no| X
    E -->|yes| G[Controlled target interaction]
    G --> R[Store outcome and evidence]
{{< /mermaid >}}

## Discord updates

Discord is how I see the system while I am away from the VPS. It is not a transcript feed. Routine cycle starts, ordinary negative results and successful scratch-space cleanup are kept in logs and durable state; they no longer generate an immediate post. Actionable leads, errors, escalation requests, findings and genuine disk pressure do. A candidate gets its own discussion thread only once it is meaningful enough to review.

The bot is intentionally thin. Agents do not send Discord messages directly. They write a durable outbox item and structured state to the database; the bot renders that state, posts the update, and records delivery. Operator decisions travel back as audited transitions or queued tasks, rather than an informal message being mistaken for authorisation. If Discord is unavailable, the research record and pending messages remain intact. If an agent stops, the last durable state is still visible.

{{< mermaid >}}
%%{init: {'theme':'base','themeVariables':{'background':'#ffffff','fontSize':'15px','primaryColor':'#dbeafe','primaryTextColor':'#0f172a','primaryBorderColor':'#1e40af','lineColor':'#334155','textColor':'#0f172a'}}}%%
flowchart TD
    A[Session or watchdog event] --> S[(Structured state and evidence pointer)]
    S --> K{Needs attention now?}
    K -->|candidate · error · actionable lead| O[Durable outbox item]
    K -->|ordinary negative · routine cleanup| D[Three-hour programme digest<br/>only when activity changed]
    D --> O
    O --> B[Discord bot posts and records delivery]
    B --> H[Human sees concise signal]
    H -->|explicit review decision| S
{{< /mermaid >}}

The digest summarises activity per programme, open and paused leads, pending second opinions, and findings awaiting review. It emits nothing for an unchanged programme. The watchdog silently removes only eligible stale session scratch directories; an actual capacity problem becomes an alert. That separation keeps Discord useful as an operational dashboard with a conversation surface, not an agent remote-control button.

## Human review

The human does not need to approve every read-only action one at a time. That would make the system decorative. The human should retain authority where a decision is externally consequential:

- accepting or changing scope assumptions;
- approving testing that needs elevated risk tolerance;
- deciding whether a candidate becomes a report;
- submitting the report;
- responding to a triager or programme owner.

The control plane represents those decisions as state transitions instead of chat messages. A finding cannot travel from a raw candidate to a submitted report just because an agent says “ready.” It must survive evidence review, independent refutation, policy triage and an explicit human transition.

{{< mermaid >}}
%%{init: {'theme':'base','themeVariables':{'background':'#ffffff','fontSize':'15px','primaryColor':'#dbeafe','primaryTextColor':'#0f172a','primaryBorderColor':'#1e40af','lineColor':'#334155','textColor':'#0f172a'}}}%%
stateDiagram-v2
    [*] --> Observation
    Observation --> Investigation: concrete hypothesis
    Investigation --> Closed: negative or blocked with reason
    Investigation --> Candidate: impact observed
    Candidate --> Closed: refuted
    Candidate --> Review: evidence + policy triage pass
    Review --> Closed: human declines / needs more proof
    Review --> Approved: human approves
    Approved --> Submitted: explicit human submission
    Submitted --> [*]
{{< /mermaid >}}

This model matches the governance emphasis in the [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework): roles and responsibilities for human-AI configurations should be explicit, not implied by who happened to be online when a model produced an answer.

## Multi-provider handoffs

It is tempting to frame multi-provider use as an intelligence competition. In practice it is an operations problem.

Different providers have different context limits, tool integrations, working-hour constraints, rate windows, cost models and failure modes. A reliable pipeline therefore routes work at session creation, records usage, and treats provider credentials as process-local authority. The default coordinator and worker do not have to share a provider, but an explicit single-provider operator window covers both so it cannot hide consumption of the other subscription.

Three rules matter more than chasing a single benchmark winner:

1. **Use a cheap path for cheap questions.** Mapping or first-contact work does not automatically merit the deepest reasoning budget.
2. **Use deep reasoning when the evidence justifies it.** A confirmed primitive, source-heavy continuation or difficult refutation can justify a stronger session.
3. **Hand off facts.** A fresh provider is useful because it is not anchored by the previous model’s narrative. Give it measurements, controls, the unresolved question and the proof standard rather than pages of reasoning to agree with.

That last pattern is closely aligned with the broader “brain and hands” separation described in Anthropic’s discussion of [managed agents](https://www.anthropic.com/engineering/managed-agents): sessions, harnesses and execution environments are separable components. Keeping them separable makes failures diagnosable.

The second-opinion queue is intentionally separate from lead storage. Saving or marking a lead for escalation does not promise an immediate expensive run. The worker that drains that queue can be paused—for example while a manually pinned single-programme window is in force—without losing the question. Before broad reactivation, older queued items need evidence- and freshness-based triage; otherwise a backlog can turn into a token-burning retry loop.

## Operations and observability

“The agent is working” is not an operational status. A useful system needs to answer:

- What programme is currently in focus?
- Which question is being investigated, and why now?
- Which policy constraints apply?
- Did the session actually make a target request?
- Did it produce evidence and a valid outcome?
- Is the review queue full?
- Is the loop still producing new evidence, qualified leads or reportable findings, or merely activity?
- Which provider capacity was consumed?

The pipeline records plans, session logs, outcome files, evidence pointers, queue state and usage. System-service health and a low-noise digest distinguish a quiet but healthy pipeline from a broken one without a Discord message for every cycle start. This is less glamorous than the agent itself, but it is the difference between a system you can improve and a system you can only hope is running.

One especially useful metric is **evidence yield**, not session count. The current continuous loop has tiered barren-cycle and per-programme budget stops, but its yield stop still counts new reportable findings rather than qualified leads. That is a known limitation, not a solved optimisation: a future rule should credit a lead only when it contains *new evidence and a discriminating next test*. Counting raw `inconclusive` outcomes would reward noise.

The next context-engineering step is similarly empirical. I want to measure how much policy, memory, prior attempts and evidence each role actually receives, then retrieve detailed history only when a question needs it. Programme rules must remain complete. The change should be judged on trace quality and evidence gained per unit of allowance, not merely on shorter prompts. [Anthropic's context-engineering guidance](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents) and [OpenAI's agent-evaluation workflow](https://developers.openai.com/api/docs/guides/agent-evals) are useful reference points, but this part remains an evaluation plan rather than a deployed claim.

## What stays manual

The most important safety control is deciding what never becomes an autonomous behaviour.

- No report submission.
- No destructive target operation.
- No broad scanning simply because a model ran out of ideas.
- No brute force or target-specific enumeration without a policy-compliant, source-backed reason.
- No “critical impact” claim based only on an exploit chain the agent did not need to execute.
- No use of target data or third-party accounts merely to make a proof more dramatic.

The pipeline may identify a path from a low-risk proof to a more serious consequence. That is not a command to take the next step. The system should document the capability, stop at the minimum necessary proof, and let the programme or human operator decide how to validate the remaining impact.

## Failures that shaped the system

The architecture is mostly a collection of scars.

| Failure mode | Design response |
|---|---|
| A model replays a known-negative payload family. | Store the exact mechanism and closing property, not just a label. |
| A long conversation loses the key precondition. | Use bounded-question sessions and hand off structured facts. |
| A candidate is technically interesting but not reportable. | Separate candidate, refuter, policy triage and human review states. |
| A session crashes after doing useful work. | Require durable evidence and a machine-readable outcome contract. |
| A loop keeps running because activity looks like progress. | Bound barren cycles and programme spend; evaluate a qualified-lead yield signal next. |
| A new browser or MCP path is added. | Treat it as a new authority boundary and test scope enforcement again. |
| A provider configuration leaks into child sessions. | Choose providers locally at session start and keep credentials outside the research workspace. |
| An inconclusive but promising observation disappears. | Keep a lead ledger with evidence, next test or reopening condition, separate from findings. |
| A continuous loop empties a weekly allowance too early. | Pace launches against observed quota and time to reset; keep an explicit human override. |
| Routine operational events bury urgent messages. | Send actionable events immediately and aggregate ordinary activity in a periodic digest. |

None of these are model problems. They are systems problems. That is encouraging: systems problems are the part we can test, version, observe and improve.

## What this post leaves out

The architecture is intentionally described at the level of invariants:

- durable state over chat memory;
- bounded hypotheses over vague objectives;
- evidence contracts over persuasive prose;
- deterministic constraints over prompt-only rules;
- independent refutation over self-confirmation;
- human authority for external consequences.

This post excludes target inventory, scope files, request formats, operator identities, model credentials, command lines, payload engineering, tool configuration and live findings. The aim is to document the operating model without publishing a copyable offensive workflow.

## Conclusion

Models can generate hypotheses much faster than I can evaluate them. The practical bottlenecks are scope, memory, proof, review and stopping conditions.

For me, the value of the pipeline is continuity. A useful result, a failed attempt and a blocked dependency are still there when I return. I can see why work ran, what it cost, where it stopped and what needs my judgement next.

## Sources

- [Google Project Zero: Project Naptime](https://projectzero.google/2024/06/project-naptime.html)
- [Anthropic: Effective harnesses for long-running agents](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents)
- [Anthropic: Scaling managed agents: decoupling the brain from the hands](https://www.anthropic.com/engineering/managed-agents)
- [Anthropic: Effective context engineering for AI agents](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents)
- [OpenAI: Agent evals](https://developers.openai.com/api/docs/guides/agent-evals)
- [Cassim Khouani, aka Aituglo](https://aituglo.com/)
- [YesWeHack: Building an LLM for Bug Bounty, interview with Aituglo](https://www.yeswehack.com/community/llms-bug-bounty-interview-aituglo)
- [ProjectDiscovery: Watching agents work](https://projectdiscovery.io/blog/watching-agents-work-a-behavioral-audit-of-offensive-security-llm-runs)
- [OWASP Cheat Sheet Series: MCP Security](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [NIST: AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST: Generative AI Profile (NIST AI 600-1)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
