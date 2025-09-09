---
title: Security Lab Tool Configuration Elastic and Velociraptor
date: 2025-08-26
categories: [Homelab, Setup]
tags: [homelab, setup, Detection Engineering, elastic, misp, opencti, velociraptor, shuffle, gitlab, openvas]
author: steve
description: Configuring up security lab with all the tools
mermaid: true
---

Now it's time to integrate OpenCTI with Elastic, and Velociraptor with Elastic.

### OpentCTI to Elastic

Elastic makes this integration very simple. Navigate to Management -> Fleet, then select Agent Policies. I just added it to the fleet server policy to have the agent on the Elastic VM collect the logs.

Click the button to add integrations and search for OpenCTI. Add the URL
> Make sure to add the port number, usually 8080
{: .prompt-info }

Then add the API key for OpenCTI, you can find this by clicking the profile button in the top right of OpenCTI and then profile. It will be under API key.

Add the integration and it will start to import the data.

### Velociraptor to Elastic
<a href="https://docs.velociraptor.app/blog/2019/2019-12-08-velociraptor-to-elasticsearch-3a9fc02c6568/">Here</a> is the official documentation from Velociraptor. 



