---
title: "AI and the Security Landscape: The Skills Gap"
date: 2026-08-17
categories: [Cybersecurity]
tags: [cybersecurity, artificial-intelligence, ai, series, skills, careers, learning]
description: AI didn't create the security skills gap, but it reshaped it. Here's what practitioners actually need to know now, what they don't, and how to keep up without setting yourself on fire.
---

*This is the fifth post in the AI and the Security Landscape series. The previous posts covered [the attacker side](https://bentleysec.com/posts/AI_as_an_Attacker_Tool/), [the defender side](https://bentleysec.com/posts/AI_as_a_Defender_tool/), and [the murky middle](https://bentleysec.com/posts/AI_Murky_Middle/). The introduction is [here](https://bentleysec.com/posts/AI_and_the_Security_Landscape/).*

---

The security industry had a skills gap long before AI showed up. Too much work, not enough people who know how to do it, and a hiring pipeline that has never quite kept pace with demand. This is not news to anyone who has tried to fill a security role recently, or been the person drowning because the last three reqs went unfilled.

AI didn't fix that. It also didn't simply make it worse. It reshaped it. It changed what "keeping up" even means, shuffled which skills matter, and added a pile of new things practitioners are suddenly expected to understand.

This post is about that reshaping, and about how to stay afloat without deciding you need a PhD in machine learning to keep doing your job. You don't. But you do need something.

## The trap of thinking you need to become a data scientist

Let's kill this one first, because it stops a lot of people before they start.

When practitioners hear "AI is changing security," a common reaction is to assume they now need to deeply understand neural networks, learn to train models, and become something halfway to a data scientist. Then they look at what that would actually take, feel overwhelmed, and quietly decide to worry about it later. Later becomes never.

Here's the reassuring part: that assumption is mostly wrong. The practitioner who thrives in an AI-shaped security world isn't necessarily the one who can implement a transformer from scratch. It's the one who understands what these tools do, where they fail, and how to push back on them. That's a very different, much more achievable skill set. It's also closer to what good security people already do than it might first appear.

You don't need to build the engine. You need to know enough about how it works to notice when it's making a weird noise.

## What actually becomes more valuable

A few skills go up in value in this environment, and most of them are things security people already have in some measure.

**Critical evaluation of tool output.** AI tools produce confident answers, and some of those answers are wrong. You have to look at what a tool is telling you and ask "is this actually right?" instead of just accepting the output because it came from something sophisticated-sounding. That ability becomes essential. Security people are, on the whole, already skeptical by temperament. That skepticism is now a core AI skill. Congratulations, your worst personality trait is an asset.

**Understanding failure modes.** You don't need to know how a model works internally. You do need to know how it fails: it hallucinates, it's confidently wrong in ways static tools aren't, it inherits the biases in its training data, and it falls apart on inputs unlike anything it was trained on. Knowing the shape of the failures lets you build processes that account for them.

**Asking good questions.** A lot of working with AI is knowing what to ask and how to frame it, both of the tool itself and of the vendors selling it. "What was this trained on? How does it handle novel inputs? What happens when it's wrong?" These are not machine-learning-expert questions. They're good-security-practitioner questions applied to a new kind of system.

**Judgment and context.** The things AI is worst at are exactly the things that become more valuable as the routine work gets automated: understanding your specific environment, weighing ambiguous tradeoffs, making calls that depend on organizational context no model has access to. The job shifts toward the parts that need a human who actually understands the situation.

## What becomes less central

This is worth naming honestly, because it affects how people should spend their time.

Some of the manual, repetitive work that has historically eaten a large share of security operations is going to be increasingly automated. Manual first-pass alert triage. Rote log review. Repetitive correlation that follows predictable patterns. These skills don't become worthless. You still need to understand the underlying work to supervise the automation of it. But building your entire value around being fast at manual triage is a shakier bet than it used to be.

The shift is from doing the repetitive work to overseeing the systems that do it, and handling the cases those systems can't. That's a real change in what the day-to-day looks like, and it rewards people who lean into the judgment-heavy parts rather than clinging to the mechanical ones.

I'll resist the urge to be falsely reassuring here. This shift is uncomfortable for some roles, and pretending otherwise doesn't help anyone. But "the boring parts get automated and the interesting parts become your job" is, for most people, a description of a better job than the one they have now.

## The genuinely new stuff you do need to learn

There's a category of things that didn't exist a few years ago that practitioners now need at least a working grasp of.

**How attackers use AI.** The material from earlier in this series: AI-enhanced phishing, deepfakes, automated reconnaissance. You can't defend against threats you don't understand, and these are now part of the threat model.

**AI-specific attack surface.** If your organization is deploying AI (it is, whether or not anyone told you), that deployment brings new vulnerabilities: prompt injection, model poisoning, data leakage through AI systems. Understanding these well enough to reason about them is becoming part of the baseline job, not a specialization.

**AI governance.** As AI gets embedded into more of the business, someone has to think about the security and privacy implications. Increasingly, that someone is the security team. What data are these systems touching? What can they access? Who's accountable when they get it wrong? Security teams are being asked these questions, ready or not.

None of these require deep ML expertise. All of them require deliberate attention, because they're new enough that you can't absorb them by osmosis the way you picked up the more established parts of the job.

## How to actually keep up without burning out

Here's the part I actually want people to take away. The failure mode isn't ignorance. It's paralysis, and burning out trying to drink from the firehose.

**Accept that you can't learn everything.** The field is moving faster than any individual can fully track. That's not a personal failing; it's the condition of the field right now. The goal isn't comprehensive knowledge. It's staying oriented: knowing enough to recognize what matters and to go deeper when something actually lands on your plate.

**Go hands-on with the tools you already have.** The highest-return thing you can do is actually use the AI features in the tools you already own. Most security platforms have shipped them. Turn them on. Poke at them. Watch where they get things right and where they fall over. Direct experience beats a hundred vendor webinars, and it's free.

**Follow a small number of good sources.** You don't need every newsletter. You need a few genuinely good ones and the discipline to ignore the rest. Signal over volume. The firehose of AI content is mostly noise, and trying to keep up with all of it is a great way to feel perpetually behind while learning very little.

**Learn in public if you can.** Write about what you're figuring out. Teach it to someone else. Give the internal brown-bag talk. Explaining something forces you to actually understand it, and it compounds. You learn faster, and you help the people around you keep up too. (This blog series is, transparently, me taking my own advice.)

**Focus on principles over specifics.** Individual tools and techniques will change fast. The underlying principles are far more durable: how these systems fail, what questions to ask, how to reason about AI risk. Put your learning time there and it keeps paying off long after any specific tool is obsolete.

## The reframe worth holding onto

The thing I keep coming back to is that AI mostly amplifies dynamics security people already live with. We have always worked with imperfect tools and noisy data. We have always had to keep learning because the ground never stopped moving. We have always had to make judgment calls under uncertainty.

AI turns those dials up. It doesn't invent a fundamentally alien situation. The disposition that makes someone good at security is the same one that lets them adapt to AI: curious, skeptical, willing to keep learning, comfortable with ambiguity. If you have that, you already have the most important thing. The specifics are learnable.

You don't need to become someone new. You need to keep being the kind of practitioner who pays attention and adapts. That's the job. It always was.

The next and final post in this series steps back to look at the bigger picture: where this is all heading, what it might mean for the profession, and how to think about a future none of us can fully predict.

---

*This is the fifth post in the AI and the Security Landscape series. The final post will step back and look at the bigger picture: the future of AI and security, and what it means for the profession.*