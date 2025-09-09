---
title: Security Lab Tool Install Part 2
date: 2025-08-21
categories: [Homelab, Setup]
tags: [homelab, setup, Detection Engineering, elastic, misp, opencti, velociraptor, shuffle, gitlab, openvas]
author: steve
description: Setting up security lab with all the tools part 2
mermaid: true
---

In part 1 we installed Elastic, OpenCTI, and MISP. Now we are going to take a look at Velociraptor, Shuffle, and Gitlab.

### Velociraptor
For endpoint forensics and hunting, I’ll install Velociraptor. The server will sit on its own VM, and later I’ll deploy agents across my test endpoints to simulate a real enterprise environment. <a href="https://docs.velociraptor.app/docs/deployment/quickstart/">Here</a> is the official documentation.

### Shuffle 
Shuffle will help me automate response and enrichment workflows. Since it’s Docker-based, the installation should be straightforward. I’ll cover how I deploy it, then hook it into my detection pipeline later. <a href="https://shuffler.io/docs/configuration">Here</a> is the official documentation.
```shell
git clone https://github.com/shuffle/Shuffle
cd Shuffle
docker-compose up -d
```

### Gitlab
To keep everything version-controlled, I’ll run GitLab for managing my detection rules and automation pipelines. I’ll start with the Omnibus package on Ubuntu. <a href="https://docs.gitlab.com/install/package/ubuntu/?tab=Community+Edition">Here</a> is the official documentation.

### Conclusion
This one is a short one, but the install guides are pretty self-explanatory.