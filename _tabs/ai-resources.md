---
title: AI Resources
icon: fas fa-robot
order: 6
---

A curated set of AI tools I actually find useful, plus the pointers that keep the security side honest. The general-purpose stuff up top, the practitioner angle further down. For the deep AI security material (red teaming, MCP security, model scanning, governance), see the [Securing AI section](https://bentleysec.com/resources/#securing-ai) on the main Resources page.

A standing caveat, because it matters: don't paste anything personal, confidential, or work-sensitive into a cloud AI you don't control. Most of them log prompts, and many train on them. If the data is sensitive, run a model locally. That principle shapes a lot of what's recommended here.

[🤖 Chatbots](#chatbots) [🏠 Local & Self-Hosted](#local-self-hosted) [🖼️ Image](#image-generation) [🎬 Video](#video-generation) [🔊 Audio & Voice](#audio-voice) [💻 Coding](#coding-assistants) [🔎 AI Search & Research](#search-research) [✍️ Prompting](#prompting) [📊 Benchmarks & Indexes](#benchmarks-indexes) [🛡️ Security Angle](#security-angle)
 
--- ## 🤖 Chatbots
 
The general-purpose assistants. Most have a usable free tier; sign-up requirements and limits change constantly, so treat specifics as a snapshot.
 
- [Claude](https://claude.ai/) — Anthropic's assistant. Strong at writing, reasoning, and code. My daily driver for long-form and technical work.
- [ChatGPT](https://chatgpt.com/) — OpenAI's assistant. The one most people mean when they say "AI." Broad tooling and ecosystem.
- [Gemini](https://gemini.google.com/) — Google's assistant, with deep integration into the Google ecosystem and a large context window.
- [Google AI Studio](https://aistudio.google.com/) — Free access to Gemini models with more knobs to turn than the consumer app. Good for prototyping prompts.
- [Microsoft Copilot](https://copilot.microsoft.com/) — GPT-backed, wired into the Microsoft 365 world.
- [DeepSeek](https://chat.deepseek.com/) — Capable open-weight models with a generous free tier.
- [Qwen](https://chat.qwen.ai/) — Alibaba's models, strong multilingual and coding performance.
- [Mistral](https://chat.mistral.ai/) — European provider with solid open-weight models and a privacy-forward posture.
- [Perplexity](https://www.perplexity.ai/) — Answer engine that cites sources. More useful than a raw chatbot when you need references.
## 🏠 Local & Self-Hosted
 
Where privacy is a concern, this is the answer. Everything here runs on your own hardware, so nothing leaves the box. Directly relevant to a homelab.
 
- [Ollama](https://ollama.com/) — The easiest on-ramp to running LLMs locally. One command to pull and run a model. Pairs well with a Proxmox VM.
- [LM Studio](https://lmstudio.ai/) — Desktop app for discovering, downloading, and chatting with local models. Good GUI for people who don't want to live in a terminal.
- [Open WebUI](https://openwebui.com/) — A self-hosted, ChatGPT-style web front end that sits on top of Ollama or any OpenAI-compatible API. The natural homelab pairing.
- [llama.cpp](https://github.com/ggml-org/llama.cpp) — The inference engine underpinning much of the local-LLM world. Runs quantized models efficiently on CPU or modest GPUs.
- [Jan](https://jan.ai/) — A fully offline, open-source desktop assistant. Privacy by default.
- [GPT4All](https://www.nomic.ai/gpt4all) — Local models with a friendly installer, aimed at running well on everyday hardware.
- [AnythingLLM](https://anythingllm.com/) — Self-hosted document chat and RAG over your own files, backed by local or hosted models.
- [Can I Run This LLM?](https://www.canirun.ai/) — Quick check on whether a given model will fit your hardware before you download 40GB of weights.
## 🖼️ Image Generation
 
- [ComfyUI](https://www.comfy.org/) — Node-based, fully local Stable Diffusion pipeline. Steep-ish learning curve, near-total control. Runs in the homelab.
- [Stability Matrix](https://lykos.ai/) — A launcher that manages local image-gen frontends and models so you don't fight dependencies.
- [Fooocus](https://github.com/lllyasviel/Fooocus) — Local image generation tuned for good defaults. Closest thing to "just type and get a nice image" while staying self-hosted.
- [Gemini / Nano Banana](https://gemini.google.com/) — Google's hosted image generation and editing, if you don't need local.
- [Civitai](https://civitai.com/) — The big index of Stable Diffusion models and LoRAs. Useful reference even if you generate elsewhere.
## 🎬 Video Generation
 
Fast-moving and mostly hosted. Expect sign-ups, credits, and short clips.
 
- [Google Flow](https://flow.google.com/) — Google's Veo-based video generation, with a daily free allotment.
- [Wan AI](https://create.wan.video/) — Image-to-video with a free daily tier.
- [FramePack](https://github.com/colinurbs/FramePack-Studio) — A local video-gen option if you have an NVIDIA GPU and want to keep it in-house.
## 🔊 Audio & Voice
 
- [ElevenLabs](https://elevenlabs.io/) — The current benchmark for realistic text-to-speech and voice work.
- [Suno](https://suno.com/) — Full song generation from a text prompt. Genuinely impressive, free daily credits.
- [Kokoro TTS](https://github.com/hexgrad/kokoro) — A small, high-quality open TTS model you can run locally.
- [Applio](https://applio.org/) — Local voice cloning and conversion. Worth understanding, since the same tech underpins voice-based social engineering (see the [attacker-tool post](/posts/AI_as_an_Attacker_Tool/)).
- [Ultimate Vocal Remover](https://ultimatevocalremover.com/) — Local stem separation, if you need to split vocals from a track.
## 💻 Coding Assistants
 
- [Claude Code](https://www.anthropic.com/claude-code) — Anthropic's agentic CLI coding tool. Strong for multi-file work and refactors.
- [Cursor](https://cursor.com/) — An AI-first code editor built on VS Code.
- [Continue](https://www.continue.dev/) — Open-source IDE assistant that works with local models via Ollama, keeping code on your machine.
- [aider](https://aider.chat/) — A terminal-based pair programmer that edits your git repo directly, model-agnostic.
## 🔎 AI Search & Research
 
General search-style assistants that cite sources, plus the more academic, paper-focused research bots.
 
### Search & answer engines
 
- [Perplexity](https://www.perplexity.ai/) — Cited answers, good for quick research where provenance matters.
- [Exa](https://exa.ai/search) — A search API and engine built for AI-style semantic queries.
- [Google AI Mode](https://google.com/aimode) — Google's AI-answer search mode, with a free tier.
- [Ask Brave](https://search.brave.com/ask) — Brave's AI answer engine, privacy-forward.
### Document & literature research
 
- [NotebookLM](https://notebooklm.google.com/) — Upload your own sources and query them. Solid for working through docs, papers, or a pile of PDFs. Can also generate audio overviews.
- [Elicit](https://elicit.com/) — Research assistant aimed at working through academic literature and systematic reviews.
- [SciSpace](https://scispace.com/) — Chat with papers, get explanations of dense passages, and search across a large literature corpus.
- [Alphaxiv](https://www.alphaxiv.org/) — A research chatbot layered over arXiv, for interrogating preprints.
- [Bohrium](https://www.bohrium.com/) — A research-focused chatbot aimed at scientific work.
- [Scinito](https://ekb.scinito.ai/ai/chat) — Another research assistant for querying academic sources.
- [Sci-Bot](https://sci-bot.ru/) — A Sci-Hub-backed research chatbot.
- [Consensus](https://consensus.app/) — Search engine that surfaces findings from peer-reviewed research and summarizes what the literature actually says.
- [PrivateGPT](https://privategpt.dev/) — Self-hosted document chat, so your source material never leaves your machine. Fits the homelab and the privacy principle up top.
### General assistants worth using for research
 
- [Claude](https://claude.ai/) — Strong at reasoning over long documents and synthesizing across sources.
- [ChatGPT](https://chatgpt.com/) — Deep Research mode does multi-step, cited investigations.
- [Gemini](https://gemini.google.com/) — Large context window and its own Deep Research mode.
## ✍️ Prompting
 
- [Prompt Engineering Guide](https://www.promptingguide.ai/) — The most thorough open guide to prompting, including adversarial and injection techniques worth understanding defensively.
- [Learn Prompting](https://learnprompting.org/) — Structured free courses, including a prompt-hacking track.
- [Anthropic's Prompt Engineering docs](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/overview) — Practical, model-specific guidance that generalizes well.
## 📊 Benchmarks & Indexes
 
For when you need to pick a model and want more than vibes.
 
- [Artificial Analysis](https://artificialanalysis.ai/) — Independent benchmarks for chat, image, and video models, plus pricing and speed.
- [LM Arena](https://arena.ai/leaderboard) — Crowd-voted head-to-head model rankings.
- [Models.dev](https://models.dev/) — A model database with capabilities and pricing.
- [LLM Pricing](https://www.llm-prices.com/) — Quick API cost comparison across providers.
- [FutureTools](https://www.futuretools.io/) — A broad directory of AI tools, filterable by free options.
--- ## 🛡️ Security Angle
 
The reason this page reads differently from a generic AI list. A few tools and references that sit at the intersection of "AI tool" and "security practitioner," pulled to the top so they're easy to find. The full treatment lives in the [Securing AI section](/resources/#securing-ai) of the main Resources page.
 
- [Ollama](https://ollama.com/) + [Open WebUI](https://openwebui.com/) — A private, self-hosted assistant stack. The single most useful setup for anyone who wants AI help without shipping sensitive data to a third party.
- [Gandalf](https://gandalf.lakera.ai/) — Lakera's browser-based prompt-injection game. The gentlest possible intro to why LLM input is dangerous.
- [Garak](https://github.com/NVIDIA/garak) — NVIDIA's LLM vulnerability scanner. Point it at a model and see what falls out.
- [PyRIT](https://github.com/Azure/PyRIT) — Microsoft's risk-identification toolkit for generative AI. For actually red-teaming a deployment.
- [OWASP Top 10 for LLMs](https://genai.owasp.org/) — The starting point for reasoning about LLM application risk.
- [MITRE ATLAS](https://atlas.mitre.org/) — The ATT&CK-style knowledge base for adversarial ML. Where to map AI threats.
- [Embrace The Red](https://embracethered.com/) — Johann Rehberger's blog, some of the best hands-on LLM and agent attack research going.

For the deep material — AI red teaming, blue teaming, MCP and agent security, model scanning, governance frameworks, vulnerable-by-design labs — head to the [Securing AI section on the Resources page](https://bentleysec.com/resources/#securing-ai). That's where I keep the serious security tooling.