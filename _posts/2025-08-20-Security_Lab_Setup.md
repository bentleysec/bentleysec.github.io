---
title: Security Lab Tool Install
date: 2025-08-20
categories: [Homelab, Setup]
tags: [homelab, setup, Detection Engineering, elastic, misp, opencti, velociraptor, shuffle, gitlab, openvas]
author: steve
description: Setting up security lab with all the tools
mermaid: true
---

For the past few posts, I’ve been talking about my goals for this home security lab: learning detection engineering, experimenting with SIEM (Mainly Elastic), working with threat intelligence (OpenCTI and MISP), and testing attacker techniques in a safe environment (OpenBAS). Up until now, it’s been mostly planning and design — today, I’m finally starting the installation process.

I’ll be deploying everything on Proxmox, which will serve as the backbone of my lab. Each service will get its own VM (or in some cases, a shared host), and I’ll tune resources as needed once things are running. Here’s the starting lineup:

### Elastic
First up is Elastic, which will be the heart of my detection engineering experiments. I’ll start with a single-node deployment (Elasticsearch, Kibana) before splitting it out later if I need more horsepower. Installation steps will include:
- Elasticsearch install and configuration
- Kibana install and configuration
- Elastic agent install and configuration

#### Elasticsearch and Kibana install and configuration
Follow the offical guide here: <a href="https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-with-debian-package">Install Elasticsearch with a Debian package</a>. 

<bold>Step 1: Import the Elasticsearch PGP key</bold>
``` bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
```

<bold>Step 2: Install Elasticsearch and Kibana</bold>
```bash
sudo apt-get install apt-transport-https
```
```bash
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list
```
```bash
sudo apt-get update && sudo apt-get install elasticsearch kibana
```

Now that Elasticsearch and Kibana are installed, we need to configure Kibana to be exposed on the external IP so that we can reach it. To do this edit the `/etc/kibana/kibana.yml` file and change the line:
```yaml
#server.host: "localhost"
```
to
```yaml
server.host: "0.0.0.0"
```
At the end of the file add the following line to enable Security, this allows Kibana to encrypt sensitive information.
```yaml
xpack.encryptedSavedObjects.encryptionKey: <"min-32-byte-long-strong-encryption-key">
```

Now it is time to start Elasticsearch and Kibana. To configure Elasticsearch to start automatically when the system boots up, run the following commands:
```bash
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable elasticsearch.service
sudo /bin/systemctl enable kibana.service
```
Now to start the services:
```bash
sudo systemctl start elasticsearch.service
sudo systemctl start kibana.service
```

Now head to your VMs IP and port 5601 to access the web portal. If you didn't grab the password during the install or would like to change it you can run this command:
```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -i -u elastic
```
> The `-i` is for interactive allowing you to set your own password. 
{: .prompt-info }

#### Fleet Server Setup
In order to use the Elastic agents you need to install the Fleet Server. Once logged into the platform navigate to Management - > Fleet. When you add a Fleet server put in the IP of your VM (it adds port 8220 automatically), for example `https://192.168.0.10`. Elastic will then create an Agent Policy for you to install the Fleet Server Agent. Elastic will then give you the commands to install the agent, I just install it on the VM which runs Elastic.

### OpenCTI
OpenCTI runs on docker, <a href="https://docs.opencti.io/latest/deployment/installation/">here</a> are the official directions. Clone the repo:
```shell
git clone https://github.com/OpenCTI-Platform/docker.git
cd docker
```

> If you plan to use the API and use a self signed cert (we will, as Elastic uses the API to pull in indicators), you need to add the following line to your docker compose file under the opencti environment variables `- APP__GRAPHQL__PLAYGROUND__FORCE_DISABLED_INTROSPECTION=false`
{: .prompt-info }

Next, create the `.env` file. The official documentation has this handy example to quickly generate it:
```shell
sudo apt install -y jq
cd ~/docker
(cat << EOF
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=ChangeMePlease
OPENCTI_ADMIN_TOKEN=$(cat /proc/sys/kernel/random/uuid)
OPENCTI_BASE_URL=http://localhost:8080
OPENCTI_HEALTHCHECK_ACCESS_KEY=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_USER=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
RABBITMQ_DEFAULT_USER=guest
RABBITMQ_DEFAULT_PASS=guest
ELASTIC_MEMORY_SIZE=4G
CONNECTOR_HISTORY_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_CSV_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_TXT_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_DOCUMENT_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_ANALYSIS_ID=$(cat /proc/sys/kernel/random/uuid)
SMTP_HOSTNAME=localhost
EOF
) > .env
```

Next, as OpenCTI has a dependency on ElasticSearch, you have to set `vm.max_map_count` before running the containers, as mentioned in the <a href="https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode">ElasticSearch documentation</a>.
```shell
sudo sysctl -w vm.max_map_count=1048575
```
To make this parameter persistent, add the following to the end of your `/etc/sysctl.conf:`
```shell
vm.max_map_count=1048575
```
Now you can start your containers by running:
```shell
docker compose up -d
```
Initialization can take a couple minutes, so be patient

### MISP

Just like OpenCTI, we are going to run MISP in docker. Here is the project in Github <a href="https://github.com/MISP/misp-docker">misp-docker</a>. Clone the repo:
```shell
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
```
Now you can start your containers by running:
```shell
docker compose up -d
```
Initialization can take a couple minutes just like OpenCTI, so be patient.

### Conclusion

We successfully installed Elastic Security, OpenCTI and MISP. Next we'll install some more tools like Velociraptor, shuffle and gitlab. Then, we'll configure all these tools to work together.
