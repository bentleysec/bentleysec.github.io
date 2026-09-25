---
title: AI Resources
icon: fas fa-robot
order: 6
---

<p>A curated set of AI tools I actually find useful, plus the pointers that keep the security side honest. The general-purpose stuff up top, the practitioner angle further down. For the deep AI security material (red teaming, MCP security, model scanning, governance), see the <a href="https://bentleysec.com/resources/#securing-ai">Securing AI section</a> on the main Resources page.</p>
 
<p>A standing caveat, because it matters: don't paste anything personal, confidential, or work-sensitive into a cloud AI you don't control. Most of them log prompts, and many train on them. If the data is sensitive, run a model locally. That principle shapes a lot of what's recommended here.</p>
 
<p>
  <a href="#chatbots">🤖 Chatbots</a> &nbsp;
  <a href="#local-self-hosted">🏠 Local &amp; Self-Hosted</a> &nbsp;
  <a href="#image-generation">🖼️ Image</a> &nbsp;
  <a href="#video-generation">🎬 Video</a> &nbsp;
  <a href="#audio-voice">🔊 Audio &amp; Voice</a> &nbsp;
  <a href="#coding-assistants">💻 Coding</a> &nbsp;
  <a href="#search-research">🔎 AI Search &amp; Research</a> &nbsp;
  <a href="#prompting">✍️ Prompting</a> &nbsp;
  <a href="#benchmarks-indexes">📊 Benchmarks &amp; Indexes</a> &nbsp;
  <a href="#security-angle">🛡️ Security Angle</a>
</p>
 
<hr>
 
<h2 id="chatbots">🤖 Chatbots</h2>
 
<p>The general-purpose assistants. Most have a usable free tier; sign-up requirements and limits change constantly, so treat specifics as a snapshot.</p>
 
<ul>
  <li><a href="https://claude.ai/">Claude</a> — Anthropic's assistant. Strong at writing, reasoning, and code. My daily driver for long-form and technical work.</li>
  <li><a href="https://chatgpt.com/">ChatGPT</a> — OpenAI's assistant. The one most people mean when they say "AI." Broad tooling and ecosystem.</li>
  <li><a href="https://gemini.google.com/">Gemini</a> — Google's assistant, with deep integration into the Google ecosystem and a large context window.</li>
  <li><a href="https://aistudio.google.com/">Google AI Studio</a> — Free access to Gemini models with more knobs to turn than the consumer app. Good for prototyping prompts.</li>
  <li><a href="https://copilot.microsoft.com/">Microsoft Copilot</a> — GPT-backed, wired into the Microsoft 365 world.</li>
  <li><a href="https://chat.deepseek.com/">DeepSeek</a> — Capable open-weight models with a generous free tier.</li>
  <li><a href="https://chat.qwen.ai/">Qwen</a> — Alibaba's models, strong multilingual and coding performance.</li>
  <li><a href="https://chat.mistral.ai/">Mistral</a> — European provider with solid open-weight models and a privacy-forward posture.</li>
  <li><a href="https://www.perplexity.ai/">Perplexity</a> — Answer engine that cites sources. More useful than a raw chatbot when you need references.</li>
</ul>
 
<h2 id="local-self-hosted">🏠 Local &amp; Self-Hosted</h2>
 
<p>Where privacy is a concern, this is the answer. Everything here runs on your own hardware, so nothing leaves the box. Directly relevant to a homelab.</p>
 
<ul>
  <li><a href="https://ollama.com/">Ollama</a> — The easiest on-ramp to running LLMs locally. One command to pull and run a model. Pairs well with a Proxmox VM.</li>
  <li><a href="https://lmstudio.ai/">LM Studio</a> — Desktop app for discovering, downloading, and chatting with local models. Good GUI for people who don't want to live in a terminal.</li>
  <li><a href="https://openwebui.com/">Open WebUI</a> — A self-hosted, ChatGPT-style web front end that sits on top of Ollama or any OpenAI-compatible API. The natural homelab pairing.</li>
  <li><a href="https://github.com/ggml-org/llama.cpp">llama.cpp</a> — The inference engine underpinning much of the local-LLM world. Runs quantized models efficiently on CPU or modest GPUs.</li>
  <li><a href="https://jan.ai/">Jan</a> — A fully offline, open-source desktop assistant. Privacy by default.</li>
  <li><a href="https://www.nomic.ai/gpt4all">GPT4All</a> — Local models with a friendly installer, aimed at running well on everyday hardware.</li>
  <li><a href="https://anythingllm.com/">AnythingLLM</a> — Self-hosted document chat and RAG over your own files, backed by local or hosted models.</li>
  <li><a href="https://www.canirun.ai/">Can I Run This LLM?</a> — Quick check on whether a given model will fit your hardware before you download 40GB of weights.</li>
</ul>
 
<h2 id="image-generation">🖼️ Image Generation</h2>
 
<ul>
  <li><a href="https://www.comfy.org/">ComfyUI</a> — Node-based, fully local Stable Diffusion pipeline. Steep-ish learning curve, near-total control. Runs in the homelab.</li>
  <li><a href="https://lykos.ai/">Stability Matrix</a> — A launcher that manages local image-gen frontends and models so you don't fight dependencies.</li>
  <li><a href="https://github.com/lllyasviel/Fooocus">Fooocus</a> — Local image generation tuned for good defaults. Closest thing to "just type and get a nice image" while staying self-hosted.</li>
  <li><a href="https://gemini.google.com/">Gemini / Nano Banana</a> — Google's hosted image generation and editing, if you don't need local.</li>
  <li><a href="https://civitai.com/">Civitai</a> — The big index of Stable Diffusion models and LoRAs. Useful reference even if you generate elsewhere.</li>
</ul>
 
<h2 id="video-generation">🎬 Video Generation</h2>
 
<p>Fast-moving and mostly hosted. Expect sign-ups, credits, and short clips.</p>
 
<ul>
  <li><a href="https://flow.google.com/">Google Flow</a> — Google's Veo-based video generation, with a daily free allotment.</li>
  <li><a href="https://create.wan.video/">Wan AI</a> — Image-to-video with a free daily tier.</li>
  <li><a href="https://github.com/colinurbs/FramePack-Studio">FramePack</a> — A local video-gen option if you have an NVIDIA GPU and want to keep it in-house.</li>
</ul>
 
<h2 id="audio-voice">🔊 Audio &amp; Voice</h2>
 
<ul>
  <li><a href="https://elevenlabs.io/">ElevenLabs</a> — The current benchmark for realistic text-to-speech and voice work.</li>
  <li><a href="https://suno.com/">Suno</a> — Full song generation from a text prompt. Genuinely impressive, free daily credits.</li>
  <li><a href="https://github.com/hexgrad/kokoro">Kokoro TTS</a> — A small, high-quality open TTS model you can run locally.</li>
  <li><a href="https://applio.org/">Applio</a> — Local voice cloning and conversion. Worth understanding, since the same tech underpins voice-based social engineering (see the <a href="/posts/AI_as_an_Attacker_Tool/">attacker-tool post</a>).</li>
  <li><a href="https://ultimatevocalremover.com/">Ultimate Vocal Remover</a> — Local stem separation, if you need to split vocals from a track.</li>
</ul>
 
<h2 id="coding-assistants">💻 Coding Assistants</h2>
 
<ul>
  <li><a href="https://www.anthropic.com/claude-code">Claude Code</a> — Anthropic's agentic CLI coding tool. Strong for multi-file work and refactors.</li>
  <li><a href="https://cursor.com/">Cursor</a> — An AI-first code editor built on VS Code.</li>
  <li><a href="https://www.continue.dev/">Continue</a> — Open-source IDE assistant that works with local models via Ollama, keeping code on your machine.</li>
  <li><a href="https://aider.chat/">aider</a> — A terminal-based pair programmer that edits your git repo directly, model-agnostic.</li>
</ul>
 
<h2 id="search-research">🔎 AI Search &amp; Research</h2>
 
<p>General search-style assistants that cite sources, plus the more academic, paper-focused research bots.</p>
 
<h3>Search &amp; answer engines</h3>
 
<ul>
  <li><a href="https://www.perplexity.ai/">Perplexity</a> — Cited answers, good for quick research where provenance matters.</li>
  <li><a href="https://exa.ai/search">Exa</a> — A search API and engine built for AI-style semantic queries.</li>
  <li><a href="https://google.com/aimode">Google AI Mode</a> — Google's AI-answer search mode, with a free tier.</li>
  <li><a href="https://search.brave.com/ask">Ask Brave</a> — Brave's AI answer engine, privacy-forward.</li>
</ul>
 
<h3>Document &amp; literature research</h3>
 
<ul>
  <li><a href="https://notebooklm.google.com/">NotebookLM</a> — Upload your own sources and query them. Solid for working through docs, papers, or a pile of PDFs. Can also generate audio overviews.</li>
  <li><a href="https://elicit.com/">Elicit</a> — Research assistant aimed at working through academic literature and systematic reviews.</li>
  <li><a href="https://scispace.com/">SciSpace</a> — Chat with papers, get explanations of dense passages, and search across a large literature corpus.</li>
  <li><a href="https://www.alphaxiv.org/">Alphaxiv</a> — A research chatbot layered over arXiv, for interrogating preprints.</li>
  <li><a href="https://www.bohrium.com/">Bohrium</a> — A research-focused chatbot aimed at scientific work.</li>
  <li><a href="https://ekb.scinito.ai/ai/chat">Scinito</a> — Another research assistant for querying academic sources.</li>
  <li><a href="https://sci-bot.ru/">Sci-Bot</a> — A Sci-Hub-backed research chatbot.</li>
  <li><a href="https://consensus.app/">Consensus</a> — Search engine that surfaces findings from peer-reviewed research and summarizes what the literature actually says.</li>
  <li><a href="https://privategpt.dev/">PrivateGPT</a> — Self-hosted document chat, so your source material never leaves your machine. Fits the homelab and the privacy principle up top.</li>
</ul>
 
<h3>General assistants worth using for research</h3>
 
<ul>
  <li><a href="https://claude.ai/">Claude</a> — Strong at reasoning over long documents and synthesizing across sources.</li>
  <li><a href="https://chatgpt.com/">ChatGPT</a> — Deep Research mode does multi-step, cited investigations.</li>
  <li><a href="https://gemini.google.com/">Gemini</a> — Large context window and its own Deep Research mode.</li>
</ul>
 
<h2 id="prompting">✍️ Prompting</h2>
 
<ul>
  <li><a href="https://www.promptingguide.ai/">Prompt Engineering Guide</a> — The most thorough open guide to prompting, including adversarial and injection techniques worth understanding defensively.</li>
  <li><a href="https://learnprompting.org/">Learn Prompting</a> — Structured free courses, including a prompt-hacking track.</li>
  <li><a href="https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/overview">Anthropic's Prompt Engineering docs</a> — Practical, model-specific guidance that generalizes well.</li>
</ul>
 
<h2 id="benchmarks-indexes">📊 Benchmarks &amp; Indexes</h2>
 
<p>For when you need to pick a model and want more than vibes.</p>
 
<ul>
  <li><a href="https://artificialanalysis.ai/">Artificial Analysis</a> — Independent benchmarks for chat, image, and video models, plus pricing and speed.</li>
  <li><a href="https://arena.ai/leaderboard">LM Arena</a> — Crowd-voted head-to-head model rankings.</li>
  <li><a href="https://models.dev/">Models.dev</a> — A model database with capabilities and pricing.</li>
  <li><a href="https://www.llm-prices.com/">LLM Pricing</a> — Quick API cost comparison across providers.</li>
  <li><a href="https://www.futuretools.io/">FutureTools</a> — A broad directory of AI tools, filterable by free options.</li>
</ul>
 
<hr>
 
<h2 id="security-angle">🛡️ Security Angle</h2>
 
<p>The reason this page reads differently from a generic AI list. A few tools and references that sit at the intersection of "AI tool" and "security practitioner," pulled to the top so they're easy to find. The full treatment lives in the <a href="/resources/#securing-ai">Securing AI section</a> of the main Resources page.</p>
 
<ul>
  <li><a href="https://ollama.com/">Ollama</a> + <a href="https://openwebui.com/">Open WebUI</a> — A private, self-hosted assistant stack. The single most useful setup for anyone who wants AI help without shipping sensitive data to a third party.</li>
  <li><a href="https://gandalf.lakera.ai/">Gandalf</a> — Lakera's browser-based prompt-injection game. The gentlest possible intro to why LLM input is dangerous.</li>
  <li><a href="https://github.com/NVIDIA/garak">Garak</a> — NVIDIA's LLM vulnerability scanner. Point it at a model and see what falls out.</li>
  <li><a href="https://github.com/Azure/PyRIT">PyRIT</a> — Microsoft's risk-identification toolkit for generative AI. For actually red-teaming a deployment.</li>
  <li><a href="https://genai.owasp.org/">OWASP Top 10 for LLMs</a> — The starting point for reasoning about LLM application risk.</li>
  <li><a href="https://atlas.mitre.org/">MITRE ATLAS</a> — The ATT&amp;CK-style knowledge base for adversarial ML. Where to map AI threats.</li>
  <li><a href="https://embracethered.com/">Embrace The Red</a> — Johann Rehberger's blog, some of the best hands-on LLM and agent attack research going.</li>
</ul>
 
<p>For the deep material (AI red teaming, blue teaming, MCP and agent security, model scanning, governance frameworks, vulnerable-by-design labs) head to the <a href="https://bentleysec.com/resources/#securing-ai">Securing AI section on the Resources page</a>. That's where I keep the serious security tooling.</p>