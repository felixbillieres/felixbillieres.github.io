---
title: "Retex: An MCP Purple Team at FIC 2026"
date: 2026-06-03
draft: false
description: "Retex of my FIC 2026 talk on an MCP-orchestrated purple team: an R&D project, born during my second year of apprenticeship, that runs attack scenarios in a GOAD lab, checks whether detection fires, mines the logs, writes a rule, tests it, and confirms coverage, all at machine speed."
summary: "I was invited to give a talk at FIC 2026 about a semester R&D project: an MCP architecture that orchestrates several home-made MCP servers to test, detect, and improve detection coverage. Attack runs in a GOAD lab, the system checks if an alert fires, digs through the logs when it does not, writes and tests a rule, then validates that the scenario is now covered. Hundreds of scenarios a month, and three good days in Lille."
tags: ["fic", "mcp", "purple-team", "detection-engineering", "ai", "soc", "goad", "exegol", "retex"]
categories: ["Events", "AI"]
featuredImage: "featured.png"
---

# Retex: An MCP Purple Team at FIC 2026

This year I was invited to give a talk at FIC 2026, the biggest cybersecurity event in Europe. The subject was a project I had been building over a few months, and the kind of thing I rarely get to present in person, so this is a short retex of both the talk and the work behind it.

## The context

I am in my second year of apprenticeship, working as a level 3 SOC analyst. The role sits at the intersection of three things I care about: offensive security, AI and ML research, and detection. For a long time those felt like separate hobbies. This project is what happened when I stopped keeping them apart and pointed all three at the same problem.

It started as an ARC. An ARC is a semester R&D project my team runs: one topic, or a few, spread over roughly four and a half months, totally free in scope. The only requirement is that the work helps improve our overall detection posture. It does not matter what the subject is as long as it moves that needle. That kind of runway, four and a half months to chase an idea wherever it goes, is rare, and it is exactly what let this one exist.

I also have to be honest about where the idea came from. I had been digging into MCP on my own for a while, mostly on the offensive and research side, and I had written a fair amount about it on this blog. The ARC was the moment that personal curiosity turned into something concrete and useful at work. Taking a topic I had only explored for fun and shipping it into a real detection workflow was, for me, the best part of the whole thing.

## From ExegolMCP to a full architecture

The starting point was [Exegol](https://exegol.com). After helping with the design and the build of the official ExegolMCP, I had a working MCP server that could drive offensive tooling from a model. That was the brick I kept reusing.

From there the question became obvious. If a model can run an attack, and a model can read logs, why not close the loop and let the whole purple team cycle run on its own? So I designed and built an orchestrator MCP server on top, coordinating several home-made MCP servers, each responsible for one slice of the job. Most of this was done in a lot of autonomy, which is its own kind of reward when it finally clicks.

The shape is a hub and spoke. The orchestrator holds the plan and decides what happens next, and each spoke is a small, focused MCP server it can call:

- an offensive server, the reused ExegolMCP, that executes techniques inside the lab,
- adversary emulation servers wired to [Caldera](https://github.com/mitre/caldera) and [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) for multi-step and atomic tests,
- a log server that searches across millions of events with Lucene queries,
- a detection backend server that exposes the live alerts and correlation signals,
- a rules server that holds the detection corpus, mapped to [MITRE ATT&CK](https://attack.mitre.org),
- and a documentation server that records each campaign and its outcome.

Keeping each capability behind its own MCP server matters more than it looks. The orchestrator never talks to a tool directly, it talks to a contract. Swapping a backend, adding a new emulation source, or testing a server in isolation does not touch the rest of the system. It also means I could grow the architecture one server at a time instead of building one giant monolith.

## The loop

The architecture runs inside a [GOAD](https://github.com/Orange-Cyberdefense/GOAD) lab where all our log collectors and detection rules are plugged in. The flow is a loop:

1. The orchestrator picks an attack scenario and executes it in the lab.
2. It checks whether an alert fires.
3. If nothing fires, it goes digging in the raw logs to find the behavioral trace the attack left behind.
4. From that trace it writes a detection rule, ElastAlert YAML with full metadata and the ATT&CK mapping.
5. It tests the rule against real data by replaying the attack and confirming the alert now fires.
6. It records the campaign, then moves to the next scenario.

The point is that you can hand it an entire scenario, or a whole batch of them, and let it run. Humans stay in charge of the final call: we review the rules it produced, check that they are coherent, and validate them before anything reaches production. The model has already proven each one by replaying the vulnerability and watching the alert come back, so the human review is about judgement, not grunt work.

Two things make this more than a script.

The first is what happens even when an alert already fires. You might expect the agent to stop there and call the scenario covered. Instead it can still go back into the logs and decide that the existing rule is too loose, that it will drown the analyst in false positives, and tighten it. So coverage is not a binary yes or no, it is a quality pass on rules that technically already work.

The second is the log correlation. When an event fires, the agent can iterate through thousands of log lines and surface the ones genuinely related to that event, including the quiet, indirect traces a human would struggle to connect by hand. That is where the machine speed really pays off: it turns a needle-in-a-haystack hunt into an input for a sharper, more precise rule. The result is detections that are both broad in coverage and narrow in noise.

Run all of that at machine speed and the numbers change shape. A human running this cycle by hand covers a handful of scenarios in a sprint. The same loop lets us create and test hundreds of scenarios a month, which moves detection coverage from something episodic, driven by the last audit, to something continuous.

## Keeping the model honest

None of this works if you trust the model blindly. A language model will happily write a rule that looks perfect and detects nothing, or one that fires on everything. Most of the design is actually about that.

There is an operating handbook with hard rules the agent cannot break, reference data so technical details resolve against verified sources like STIX and the ATT&CK index instead of being invented, structural validation that tries to falsify every output before it is accepted, persistent memory so feedback survives between runs, and skills that encode the trickier workflows. The full breakdown is in the technical write-up linked at the end.

## Three days in Lille

Being invited by my company to present this at FIC was, honestly, a great feeling. There is something specific about getting that kind of recognition for work done during an apprenticeship, and about being handed the stage at the largest cyber event in Europe to talk about it.

The talk itself was a good forcing function. Explaining the architecture to a room makes you confront the parts you hand-waved over, and the questions afterward were sharper than any code review. The recurring one was about trust, the same theme as above: how do you stop the model from inventing detections that look right and catch nothing? That is the whole game.

But the three days were really about the people. Lille during FIC is dense, conversations everywhere, old contacts you only ever see at events like this and new ones you did not expect. That is the part you cannot get from a stream.

## What comes next

For now the whole thing lives in a lab, driven by hosted models like Claude, on non-sensitive data only. That boundary is on purpose. The direction I am most excited to explore is the next one: running local models and adapting the MCP so it can operate directly inside client environments, for incident response and false positive qualification, at scale and at high precision.

The shape would be the same loop, pointed the other way. An alert fires on a client. The MCP goes straight to the logs, pulls the full history of the source, gathers every related client comment and context note, and starts looking for patterns a level 1 analyst would never have the time to see. It maps what is legitimate and what is not, and it renders a verdict.

We already tried a small version of this on low-stakes events, like a log loss alert, which is a perfect warm-up. A source stops sending logs, the alert pops, the model ingests everything tied to that source, runs a pile of queries, and comes back with a read: known issue or not. Maybe it is a maintenance window the client runs every two months and has already declared, in which case the alert qualifies itself.

The interesting part is pushing that same reasoning toward heavier signals. Picture a SAM dump alert, the kind of thing that is critical by default. Instead of paging someone immediately, the model pulls the context, notices that it lines up with an authorized credential-hygiene audit the client's own team had scheduled and documented, and legitimizes the action with the evidence to back it. Same event, very different verdict, and the analyst gets a qualified case instead of a raw alarm.

The list of things you could build on top of this is close to endless. We will see if next year I have an improvement worth bringing back to the FIC stage.

If you want the full server breakdown, the rule generation engine, and the hallucination mitigation design in detail, I wrote it up here: [Purple Team: quand l'IA orchestre la défense](https://www.itrust.fr/purple-team-quand-lia-orchestre-la-defense).

Thanks to everyone who came to the talk and pushed back on the ideas. That is the best part of these events.
