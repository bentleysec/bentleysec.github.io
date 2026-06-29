---
title: "AI and the Security Landscape: AI as an Attacker Tool"
date: 2026-06-09
categories: [Cybersecurity]
tags: [cybersecurity, artificial-intelligence, ai, series, threat-landscape, phishing, malware, deepfakes]
description: AI has handed attackers a significant upgrade — better phishing, automated reconnaissance, polymorphic malware, and a dramatically lower skill floor. Here's what that actually looks like in practice.
---

*This is the second post in the AI and the Security Landscape series. If you missed the introduction, you can find it [here](https://bentleysec.com/posts/AI_and_the_Security_Landscape/).*

---

Let's start with the uncomfortable part.

When a powerful new technology arrives, offense figures it out before defense does. This isn't new, it's basically a law of nature in security. Attackers are motivated, often well-resourced, and unburdened by the organizational friction that slows defenders down. They don't need change advisory boards. They don't need to file tickets. They don't need to wait for other teams to implement a specific change.

AI fits the pattern. And in some ways, it's the starkest example of it we've seen in a while.

This post is about what AI looks like in the hands of attackers, not as a theoretical future risk, but as a present-day operational reality that's already changing what we're up against.

## The death of the obvious phishing email

There used to be a reliable heuristic for spotting phishing: look for the typos, the awkward phrasing, the inexplicable urgency about your "suspended" account. It wasn't a perfect signal, but it was a useful one. The volume of obviously bad phishing was high enough that most people developed a reasonable intuition for it.

That era is over.

Large language models can produce phishing emails that are grammatically flawless, contextually appropriate, and professionally written all at an industrial scale, with minimal human effort. More importantly, they can be personalized. An attacker who has done even basic reconnaissance can feed that information into a prompt and generate a convincing spear phishing email in seconds. The kind of targeted, research-intensive attack that used to require real skill is now accessible to anyone with an internet connection and a basic ability to write a prompt.

The old advice, "look for spelling mistakes," "be suspicious of urgent language", isn't just outdated. It's actively dangerous. It creates false confidence in a heuristic that no longer works. A perfectly written email from what appears to be your CEO, referencing a project you're actually working on, asking you to do something plausible is now something any moderately motivated attacker can produce.

Not "AI will eventually make phishing better." It already has.

## Deepfakes: past the novelty stage

A few years ago, deepfakes were an interesting parlor trick. Impressive, somewhat unnerving, mostly confined to celebrity face-swaps and the occasional political satire video. That window has closed.

Deepfake technology has matured into a credible attack vector in enterprise environments. Voice cloning can reproduce someone's voice from a relatively small audio sample enough to make a convincing phone call or defeat a voice-based authentication system. Video deepfakes have been used in real attacks, not just proof-of-concept demonstrations.

The most cited example is the 2024 case where a finance employee at a multinational firm transferred $25 million after a video call that appeared to show his CFO and other colleagues authorizing the transaction. Everyone on the call was a deepfake. The employee had no reason to be suspicious. He transferred the money.

That story gets dismissed as an outlier, extraordinary circumstances, unusual target, unlikely to happen to most organizations. Maybe. But the underlying capability is not going away, and the cost of deploying it keeps dropping. Voice cloning in particular is already cheap and accessible enough that it's showing up in more routine fraud: fake IT support calls, CEO fraud variants, social engineering attacks where the voice is the proof of identity.

The uncomfortable truth: verbal confirmation from someone who sounds like your colleague is no longer a reliable verification method. Neither, increasingly, is video. The attack surface on human trust just got wider.

## Automated reconnaissance: the unglamorous part that matters a lot

Reconnaissance is boring. It's also, from an attacker's perspective, enormously important. The more you know about a target before you act, the better your chances of success and the lower your chances of detection.

Thorough reconnaissance used to require real time and effort: scraping LinkedIn for employee names and roles, mapping organizational structure, identifying technologies in use, finding publicly exposed services, correlating data from multiple sources. Not hard, exactly, but slow, tedious, and manual.

AI compresses all of that. Automated tools can now scrape, correlate, and synthesize target information at a speed no human team could match. Job postings reveal technology stacks. Social media reveals org structure and relationships. Public code repositories reveal internal tooling and, occasionally, credentials. OSINT that used to take days can be assembled in hours, automatically, and fed directly into the next phase of an attack.

Better reconnaissance means better attacks across the board. Phishing gets more personalized. Social engineering scripts get more convincing. Attack vector selection gets sharper. AI makes all of it cheap and fast.

## Polymorphic malware and the signature problem

Traditional malware detection has a structural weakness: it's reactive. You have to see a piece of malware, analyze it, extract signatures, and distribute them to detection tools before they can catch it. Attackers have always been able to stay ahead of this by modifying their code between deployments, change enough bytes and the signature no longer matches.

AI makes that trivial. Polymorphic malware that rewrites itself to evade known signatures isn't a new idea, but AI dramatically lowers the effort required to produce it. What used to require a skilled malware author can now be partially or fully automated. Variant generation that once required real human work can run continuously, producing novel samples faster than signature databases can be updated.

This is part of why behavioral detection has become more important than ever. If you can't rely on recognizing what the malware looks like, you have to focus on recognizing what it does. Harder problem. More durable answer.

## The skill floor just dropped

Less flashy than deepfakes or polymorphic malware. Possibly the most significant shift on this list.

Sophisticated attacks used to require sophisticated attackers. Developing custom malware, crafting convincing social engineering campaigns, moving through an enterprise network without triggering detection. These things required real expertise, built up over time. The barrier to entry filtered out a significant portion of potential threat actors.

AI erodes that barrier considerably. Script kiddies, low-skill attackers who use tools they don't fully understand, now have access to capabilities that previously required genuine expertise. An LLM can explain attack techniques, help write functional exploits, generate convincing phishing content, and walk an attacker through a campaign step by step. It won't replace a skilled nation-state actor. But it gives a low-skill attacker a real upgrade.

More attackers can attempt more capable attacks than before. The long tail of threat actors, the ones that weren't previously much of a concern because they lacked capability, just got more dangerous.

## AI-generated disinformation as a precursor

This one sits at the edges of what most security teams think about. Worth including anyway, because it's increasingly showing up as a component of more sophisticated attacks.

AI can generate disinformation at scale, fake news articles, fake social media personas, fake reviews, fake employee profiles. On its own, that's more of a societal problem than a security one. But as a precursor to targeted social engineering, it's useful to attackers in ways it wasn't before. Someone trying to manipulate a specific person can now construct a more convincing false context around their approach: fake professional profiles, fake shared connections, fake organizational scaffolding that makes the whole thing look legitimate.

Not every attack uses this. For targeted, high-value campaigns, it's real.

## What this actually means for practitioners

None of this is meant to be paralyzing. It's meant to be accurate.

The old heuristics look for typos, verify with a phone call, trust signatures are less reliable than they used to be. The volume and sophistication of attacks is rising at the same time. The honest response isn't to update your phishing training to say "AI phishing is also bad now" and call it done. It's to revisit the assumptions underlying your controls and ask which ones depended on attacker limitations that AI has eroded.

Some questions worth actually sitting with:

- Which of your verification processes rely on voice or video as a trust signal?
- How much of your detection depends on known signatures versus behavioral analysis?
- What does your attack surface look like to an attacker with AI-assisted reconnaissance?
- Which of your users are high-value enough that a personalized, AI-generated spear phishing campaign would be worth the, now minimal, effort?

The next post covers the other side of the equation: AI as a defender tool. Which is, I'll say now, genuinely encouraging. But you need to understand the threat before you can honestly evaluate the defense.

---

*This is the second post in the AI and the Security Landscape series. The next post will cover AI as a defender tool — where it genuinely helps, and where the hype outpaces the reality.*