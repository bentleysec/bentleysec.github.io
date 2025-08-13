---
title: So it Begins
date: 2025-08-13
categories: [Homelab, Setup]
tags: [homelab, setup, Detection Engineering]
author: steve
description: The beginnings of my homelab
mermaid: true
---

All things have a beginning, before I start racking servers and spinning up VMs, I wanted to put my plan on paper; or in this case, in a blog post. This is my blueprint for a security-focused home lab: a space where I can experiment with detection engineering, dive into OS internals, and learn how to identify and investigate attacker behavior.

The lab isn’t online yet. This is the design stage, the “how everything should fit together” map before I start building. I want a clear direction before I start.

My goal is to create an environment that lets me study not just the tools, but also the data, processes, and workflows that turn raw logs into actionable detections.

### What I'm Learning
My learning path is divided into four interconnected pillars:

1. Detection Engineering
I want to go beyond “install SIEM, use default alerts” and truly understand the craft of designing, testing, tuning, and automating detection rules. That means experimenting with Detection-as-Code practices, version control, CI/CD pipelines for rules, and tracking detection coverage against known threats.

2. Linux Logging & Internals
Linux often plays the vital role of server, gateway, or attacker playground in real-world environments. I’m exploring tools like auditd, syslog, journald, and endpoint telemetry to see what’s possible, what’s noisy, and what’s missing. Along the way, I’m learning how the kernel handles processes, files, and network activity and where the best hooks for detection really are.

3. Windows Logging & Internals
Windows endpoints and servers are rich with telemetry, if you know how to collect it. I’m digging into Event IDs, PowerShell logging, Sysmon configurations, and the subtleties of security auditing. The goal is to understand both the strengths and blind spots of Windows logging, and how attacker tradecraft fits into that picture.

4. Attacker Techniques
A big part of detection is understanding the “why” and “how” behind an attacker’s actions. I’ll be designing simulations for common techniques, from credential dumping to living-off-the-land—and mapping how they appear in logs across different systems.

### Lab Strategy

The blueprint calls for more than just dropping in popular security tools, I want an integrated detection ecosystem where each piece supports the others:
- Elastic Stack – My main SIEM platform for log ingestion, detection rule authoring, and dashboarding.
- MISP – To manage threat intelligence feeds, track indicators, and enrich detections with real-world data.
- OpenCTI – To organize threat intel into a structured knowledge base and link it to detection engineering work.
- GitLab – My version control for detection rules, configurations, and automation scripts. This is where Detection-as-Code lives.
- Shuffle (SOAR) – For automating workflows like indicator ingestion, case enrichment, and repetitive response tasks.
- Velociraptor – For targeted endpoint forensics and fast investigative queries when I want to see exactly what’s going on.

In the final design, threat intel will feed into detections, detections will trigger automations, and automations will loop back into refining intel and improving rules.

### What's Next
Over the next posts, I’ll walk through:
- How I’m planning my Linux and Windows log collection strategy.
- What my detection rule pipeline will look like in GitLab.
- How I’ll simulate attacker techniques to validate detections.
- The integrations that will connect my SIEM, SOAR, and threat intel tools into a cohesive workflow.

This is my blueprint stage where ideas are still flexible and improvements can be made. By the time I’m done building, I’ll have both a functional home lab and a documented path others can adapt for their own learning.

