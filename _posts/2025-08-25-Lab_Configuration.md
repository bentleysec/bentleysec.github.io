---
title: Security Lab Tool Configuration
date: 2025-08-25
categories: [Homelab, Setup]
tags: [homelab, setup, Detection Engineering, elastic, misp, opencti, velociraptor, shuffle, gitlab, openvas]
author: steve
description: Configuring up security lab with all the tools
mermaid: true
---

In my last post, I finished installing MISP and OpenCTI as part of my home security lab. With both platforms online, the next challenge is making them useful: getting data in. Out of the box, neither tool comes pre-loaded with threat intelligence — they need to be connected to feeds and each other.

This post covers:
- Setting up MISP feeds to start pulling in threat indicators
- Configuring OpenCTI connectors to ingest and organize threat data
- Connecting MISP and OpenCTI together so they enrich each other

### MISP
MISP is designed to be a collector and sharer of threat intelligence. To make it valuable, you’ll want to subscribe to feeds: curated sources of IOCs (IPs, domains, hashes, URLs, etc.).

#### Add Feeds
1. Log into MISP as an admin
2. Navigate to Sync Actions → List Feeds.
3. At this point you can use the default feeds CIRCL OSINT Feed and The Botvrij.eu Data, or you can add more from <a href="https://github.com/MISP/MISP/blob/2.4/app/files/feed-metadata/defaults.json">MISP Feeds</a>
4. If adding additional feeds, click on <bold>Import Feeds from JSON</bold> and copy and paste the JSON from Gtihub into the provided box, then click `add`.
5. Now we can enable the feeds, click on the feeds you'd like to enable or you can click them all on the page and click `Enable Selected`.
6. Make sure to go through each page to enable all the feeds you want. 
7. After you have enabled all the feeds you want, click on the box `Fetch and Store all Feed Data`, that will start the process of downloading all the feeds
8. It will take some time, you can click on <bold>Administration -> Jobs</bold> to see the status of the feeds.

### OpenCTI
To import data into OpenCTI, you need to add connectors to your docker-compose file. You can find a list of connectors <a href="https://github.com/OpenCTI-Platform/connectors/tree/master/external-import">here</a>. For MISP, we are going to use the <a href="https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/misp-feed">MISP-Feed</a> connector. Essentially, we need to add a section to our docker-compose file for OpenCT to enable this connector. 

First, we need to create an API key in MISP to integrate OpenCTI. In MISP click on your username in the top right corner, which will bring you to my profile.

Click on `Auth keys` and then `+Add authentication key`

Add a comment like "OpenCTI"

Once the key is created, make sure to copy it and save it somewhere safe.

Add the service to your docker compose file, here is an example of mine:
```yaml
  connector-misp:
    image: opencti/connector-misp:6.7.14
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=a5a7c1ae-8a43-49f7-9e3f-9dcd5be6eb31
      - CONNECTOR_NAME=MISP
      - CONNECTOR_SCOPE=misp
      - CONNECTOR_LOG_LEVEL=error
      - CONNECTOR_EXPOSE_METRICS=false
      - MISP_URL=https://192.168.100.22/ # Required
      - MISP_REFERENCE_URL= # Optional, will be used to create external reference to MISP event (default is "url")
      - MISP_KEY=ciSPAI3DN1pG6eLJFR41WJixf55vs5AEgqE2itnK # Required
      - MISP_SSL_VERIFY=false # Required
      - MISP_DATETIME_ATTRIBUTE=timestamp # Required, filter to be used in query for new MISP events
      - MISP_DATE_FILTER_FIELD=timestamp # Required, field to filter on date
      - MISP_REPORT_DESCRIPTION_ATTRIBUTE_FILTER= # Optional, filter to be used to find the attribute with report description (example: "type=comment,category=Internal reference")
      - MISP_CREATE_REPORTS=true # Required, create report for MISP event
      - MISP_CREATE_INDICATORS=true # Required, create indicators from attributes
      - MISP_CREATE_OBSERVABLES=true # Required, create observables from attributes
      - MISP_CREATE_OBJECT_OBSERVABLES=true # Required, create text observables for MISP objects
      - MISP_CREATE_TAGS_AS_LABELS=true # Optional, create tags as labels (sanitize MISP tag to OpenCTI labels)
      - MISP_GUESS_THREAT_FROM_TAGS=false # Optional, try to guess threats (threat actor, intrusion set, malware, etc.) from MISP tags when they are present in OpenCTI
      - MISP_AUTHOR_FROM_TAGS=false # Optional, map creator:XX=YY (author of event will be YY instead of the author of the event)
      - MISP_MARKINGS_FROM_TAGS=false # Optional, map marking:XX=YY (in addition to TLP, add XX:YY as marking definition, where XX is marking type, YY is marking value)
      - MISP_ENFORCE_WARNING_LIST=false # Optional, enforce warning list in MISP queries
      - MISP_REPORT_TYPE=misp-event # Optional, report_class if creating report for event
      - MISP_IMPORT_FROM_DATE=2000-01-01 # Required, import all event from this date
      - MISP_IMPORT_TAGS= # Optional, list of tags used to filter events to import
      - MISP_IMPORT_TAGS_NOT= # Optional, list of tags to not include
      - MISP_IMPORT_CREATOR_ORGS= # Optional, only import events created by those orgs (put the identifiers here)
      - MISP_IMPORT_CREATOR_ORGS_NOT= # Optional, do not import events created by those orgs (put the identifiers here)
      - MISP_IMPORT_OWNER_ORGS= # Optional, only import events owned by those orgs (put the identifiers here)
      - MISP_IMPORT_OWNER_ORGS_NOT= # Optional, do not import events owned by those orgs (put the identifiers here)
      - MISP_IMPORT_KEYWORD= # Optional, search only events based on a keyword
      - MISP_IMPORT_DISTRIBUTION_LEVELS= # Optional, only import events with the given distribution levels (ex: 0,1,2,3)
      - MISP_IMPORT_THREAT_LEVELS= # Optional only import events with the given threat levels (ex: 1,2,3,4)
      - MISP_IMPORT_ONLY_PUBLISHED=false
      - MISP_IMPORT_WITH_ATTACHMENTS=false # Optional, try to import a PDF file from the attachment attribute
      - MISP_IMPORT_TO_IDS_NO_SCORE=40 # Optional, use as a score for the indicator/observable if the attribute to_ids is no
      - MISP_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT=false #  Optional, import unsupported observable as x_opencti_text
      - MISP_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT_TRANSPARENT=true #  Optional, import unsupported observable as x_opencti_text just with the value
      - MISP_INTERVAL=5 # Required, in minutes
      - MISP_PROPAGATE_LABELS=false # Optional, propagate labels to the observables
    restart: always
    depends_on:
      opencti:
        condition: service_healthy
```
Make sure to change the lines:
```yaml
- OPENCTI_URL=http://opencti:8080
- OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
- CONNECTOR_ID=a5a7c1ae-8a43-49f7-9e3f-9dcd5be6eb31
- MISP_URL=https://192.168.100.22/ # Required
- MISP_KEY=ciSPAI3DN1pG6eLJFR41WJixf55vs5AEgqE2itnK # Required
```
Start OpenCTI with `docker compose up -d` and it should automatically start importing the data from MISP.

