---
title: "A New AI Resources Page"
date: 2026-08-25
categories: [AI]
tags: [ai, artificial-intelligence, resources, tools]
description: I've added a curated AI Resources page to the site. A mix of the general-purpose AI tools I actually use and the security angle I can't help bringing to everything.
---

After spending six posts working through [AI and the Security Landscape](https://bentleysec.com/posts/AI_and_the_Security_Landscape/), I kept running into the same small problem. People would ask what AI tools I actually use, and I'd send them a messy handful of links from memory, usually forgetting half of them.

So I've fixed that. There's now an [AI Resources page](https://bentleysec.com/ai-resources/) in the nav.

It's a curated list rather than an exhaustive one. Plenty of sites already try to catalog every AI tool in existence, and they're useful, but "every tool" is its own kind of noise. This is the shorter list: the things I've actually found worth using, organized so you can find them.

A few things it covers:

The general-purpose stuff. Chatbots, image and video generation, audio and voice, coding assistants, research tools. The tools most people mean when they talk about AI.

The local and self-hosted angle. This is where my homelab bias shows. If you care about privacy, or you just don't want to ship sensitive data to someone else's servers, running models locally with Ollama and Open WebUI is the answer, and I've pointed at the pieces that make that straightforward.

The security lens. I can't write a resource list without it. There's a section pulling together the AI tools and references that matter from a practitioner's point of view, and it links through to the deeper [Securing AI material](https://bentleysec.com/resources/#securing-ai) on the main Resources page, which is where the serious red-teaming, MCP security, and governance tooling lives.

One thing I put at the top of the page and will repeat here, because it's the single most important habit: don't paste anything personal, confidential, or work-sensitive into a cloud AI you don't control. Most of them log your prompts. Many train on them. If the data is sensitive, run a model locally instead. That one principle shapes a lot of the recommendations.

The page will change over time. This space moves fast enough that any list is out of date the moment it's published, so I'll prune and update as tools come and go. If there's something genuinely useful I've missed, I'd like to hear about it.

Go have a look: [AI Resources](https://bentleysec.com/ai-resources/).