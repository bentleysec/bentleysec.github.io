---
title: Monitoring Proxmox with Prometheus and Grafana
date: 2025-12-22
categories: [cybersecurity, monitoring, grafana, prometheus, proxmox, homelab]
tags: [homelab, monitoring]
author: steve
description: This guide walks you through setting up comprehensive monitoring for your Proxmox server and all its VMs using Prometheus and Grafana.
mermaid: true
---

## Architecture Overview
- **Proxmox VE Exporter**: Collects metrics from Proxmox API (runs on monitoring VM)
- **Node Exporter**: Collects system metrics from Proxmox host and VMs
- **Prometheus**: Stores and queries metrics (runs on monitoring VM)
- **Grafana**: Visualizes metrics with dashboards (runs on monitoring VM)

## Prerequisites
- Proxmox VE server (version 6.x or 7.x+)
- A dedicated VM for monitoring stack (Ubuntu/Debian recommended, 2 CPU cores, 4GB RAM, 20GB disk)
- Basic Linux command line knowledge
- Root access to Proxmox host and monitoring VM

## Setup Overview

**On Proxmox Host**: Only Node Exporter to collect host metrics

**On Monitoring VM**: Prometheus, Grafana, PVE Exporter, and Node Exporter

**On Other VMs (optional)**: Node Exporter for per-VM metrics

### Part 1: Install Node Exporter on Proxmox Host
On Proxmox host

#### 1.1 Download and Install
``` bash
cd /tmp
wget https://github.com/prometheus/node_exporter/releases/download/vX/node_exporter-X.linux-amd64.tar.gz
tar xvf node_exporter-X.linux-amd64.tar.gz
cp node_exporter-X.linux-amd64/node_exporter /usr/local/bin/
useradd --no-create-home --shell /bin/false node_exporter
chown node_exporter:node_exporter /usr/local/bin/node_exporter
```

> Make sure to get the latest version from <a href="https://prometheus.io/download/#node_exporter">Prometheus</a>
{: .prompt-info }

#### 1.2 Create Systemd Service

Create `/etc/systemd/system/node_exporter.service`:

``` ini
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
```

#### 1.3 Start Node Exporter

``` bash
systemctl daemon-reload
systemctl start node_exporter
systemctl enable node_exporter
systemctl status node_exporter
```

#### 1.4 Verify It's Running
``` bash
curl http://localhost:9100/metrics
```

You should see metrics output. The Proxmox host setup is now complete!

### Part 2: Create Monitoring User in Proxmox

On the Proxmox Web GUI:
1. Go to Datacenter → Permissions → Users
2. Click "Add" and create user:`Prometheus`
3. Set Realm to `Proxmox VE authentication server`
4. Set a strong password (you'll need this later)
5. Go to Permissions → Add → User Permission
6. Path: `/`
7. User: `prometheus@pve`
8. Role: `PVEAuditor`
9. Click "Add"

### Part 3: Setup Monitoring VM

From this point forward, SSH into your monitoring VM and run all commands there.

#### 3.1 Install Prometheus

Create Prometheus User
```bash
sudo useradd --no-create-home --shell /bin/false prometheus
```

Download and Install Prometheus
```bash
cd /tmp
wget https://github.com/prometheus/prometheus/releases/download/vX/prometheus-X.linux-amd64.tar.gz
tar xvf prometheus-X.linux-amd64.tar.gz
cd prometheus-X.linux-amd64

sudo cp prometheus /usr/local/bin/
sudo cp promtool /usr/local/bin/
sudo chown prometheus:prometheus /usr/local/bin/prometheus
sudo chown prometheus:prometheus /usr/local/bin/promtool
```

> Replace X with the latest version from <a href="https://prometheus.io/download/">Prometheus</a>
{: .prompt-info }

Create Directories
```bash
sudo mkdir /etc/prometheus
sudo mkdir /var/lib/prometheus
sudo chown prometheus:prometheus /etc/prometheus
sudo chown prometheus:prometheus /var/lib/prometheus
```

Create Configuration Files
```bash
sudo touch /etc/prometheus/consoles
sudo touch /etc/prometheus/console_libraries
sudo chown -R prometheus:prometheus /etc/prometheus/consoles
sudo chown -R prometheus:prometheus /etc/prometheus/console_libraries
```

#### 3.2 Install Node Exporter on Monitoring VM

Download and Install

``` bash
cd /tmp
wget https://github.com/prometheus/node_exporter/releases/download/vX/node_exporter-X.linux-amd64.tar.gz
tar xvf node_exporter-X.linux-amd64.tar.gz
sudo cp node_exporter-X.linux-amd64/node_exporter /usr/local/bin/
sudo useradd --no-create-home --shell /bin/false node_exporter
sudo chown node_exporter:node_exporter /usr/local/bin/node_exporter
```

> Make sure to get the latest version from <a href="https://prometheus.io/download/#node_exporter">Prometheus</a>
{: .prompt-info }

Create Systemd Service

Create `/etc/systemd/system/node_exporter.service`:
```ini
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
```

Start Node Exporter
```bash
sudo systemctl daemon-reload
sudo systemctl start node_exporter
sudo systemctl enable node_exporter
sudo systemctl status node_exporter
```

#### 3.3  Install Proxmox VE Exporter

Install Dependencies
```bash
sudo apt update
sudo apt install -y python3-pip python3-venv
```

Install PVE Exporter
```bash
sudo pip3 install prometheus-pve-exporter
```

Create Configuration File

Create `/etc/prometheus/pve.yml`
```yaml
default:
  user: prometheus@pve
  password: your_password_here
  # Replace with your Proxmox host IP or hostname
  target: https://192.168.1.100:8006
  verify_ssl: false
```

> Important: Replace `your_password_here` with the password you set for the `prometheus@pve` user, and replace `192.168.1.100` with your actual Proxmox host IP address.
{: .prompt-info }

Set Permissions
```bash
sudo chown prometheus:prometheus /etc/prometheus/pve.yml
sudo chmod 600 /etc/prometheus/pve.yml
```

Create Systemd Service for PVE Exporter

Create `/etc/systemd/system/pve_exporter.service`:
```ini
[Unit]
Description=Proxmox VE Exporter
After=network.target

[Service]
Type=simple
User=prometheus
ExecStart=/usr/local/bin/pve_exporter /etc/prometheus/pve.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Start PVE Exporter
```bash
sudo systemctl daemon-reload
sudo systemctl start pve_exporter
sudo systemctl enable pve_exporter
sudo systemctl status pve_exporter
```

Verify It's Working
```bash
curl http://localhost:9221/pve
```

You should see Proxmox metrics. If you get connection errors, check:
- The Proxmox host IP in `/etc/prometheus/pve.yml` is correct
- The monitoring VM can reach the Proxmox host on port 8006
- The `prometheus@pve` user credentials are correct

#### 3.4 Configure Prometheus

Create `/etc/prometheus/prometheus.yml`:
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  # Prometheus itself
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  # Monitoring VM metrics
  - job_name: 'monitoring-vm'
    static_configs:
      - targets: ['localhost:9100']
        labels:
          instance: 'monitoring-vm'

  # Proxmox host metrics
  - job_name: 'proxmox-host'
    static_configs:
      - targets: ['192.168.1.100:9100']  # Replace with your Proxmox host IP
        labels:
          instance: 'proxmox-host'

  # Proxmox VE metrics (VMs, containers, storage, etc.)
  - job_name: 'proxmox'
    static_configs:
      - targets:
        - 'localhost:9221'
    metrics_path: /pve
    params:
      target: ['192.168.1.100'] # Replace with your Proxmox host IP
      module: [default]

  # Other VMs (optional - add after installing node_exporter on them)
  - job_name: 'other-vms'
    static_configs:
      - targets: 
        - 'vm1-ip:9100'
        - 'vm2-ip:9100'
        labels:
          group: 'vms'
```

> Important: Replace `192.168.1.100` with your actual Proxmox host IP address.
{: .prompt-info }

Set Permissions
```bash
sudo chown prometheus:prometheus /etc/prometheus/prometheus.yml
```

Create Prometheus Systemd Service

Create `/etc/systemd/system/prometheus.service`:
```ini
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/var/lib/prometheus/ \
  --web.console.templates=/etc/prometheus/consoles \
  --web.console.libraries=/etc/prometheus/console_libraries

[Install]
WantedBy=multi-user.target
```

Start Prometheus
```bash
sudo systemctl daemon-reload
sudo systemctl start prometheus
sudo systemctl enable prometheus
sudo systemctl status prometheus
```

Verify Prometheus is running: `http://your-monitoring-vm-ip:9090`

#### 3.5 Install Grafana

Install Grafana
```bash
sudo apt-get install -y software-properties-common
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt-get update
sudo apt-get install grafana
```

Start Grafana
```bash
sudo systemctl start grafana-server
sudo systemctl enable grafana-server
sudo systemctl status grafana-server
```

Access Grafana

Open `http://your-monitoring-vm-ip:3000`
- Default username: `admin`
- Default password: `admin`
- Change password on first login

Add Prometheus Data Source
1. Click Settings (gear icon) → Data Sources
2. Click "Add data source"
3. Select "Prometheus"
4. Set URL: `http://localhost:9090`
5. Click "Save & Test"

### Part 4: Install Node Exporter on Other VMs (Optional)

For each additional VM you want detailed metrics from, SSH into it and run:
``` bash
cd /tmp
wget https://github.com/prometheus/node_exporter/releases/download/vX/node_exporter-X.linux-amd64.tar.gz
tar xvf node_exporter-X.linux-amd64.tar.gz
sudo cp node_exporter-X.linux-amd64/node_exporter /usr/local/bin/
sudo useradd --no-create-home --shell /bin/false node_exporter
sudo chown node_exporter:node_exporter /usr/local/bin/node_exporter
```

> Make sure to get the latest version from <a href="https://prometheus.io/download/#node_exporter">Prometheus</a>
{: .prompt-info }

**Create Systemd Service**

Create `/etc/systemd/system/node_exporter.service`:

``` ini
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
```

**Start Node Exporter**

``` bash
sudo systemctl daemon-reload
sudo systemctl start node_exporter
sudo systemctl enable node_exporter
sudo systemctl status node_exporter
```

**Verify It's Running**
``` bash
curl http://localhost:9100/metrics
```

### Part 5: Import Grafana Dashboards

RUN IN GRAFANA WEB INTERFACE (on monitoring VM)
1. Click "+" → Import
2. Enter dashboard ID: `10347` (Proxmox via Prometheus)
3. Select your Prometheus data source
4. Click "Import"

**Import Node Exporter Dashboard**

1. Click "+" → Import
2. Enter dashboard ID: `1860` (Node Exporter Full)
3. Select your Prometheus data source
4. Click "Import"

### Part 5: Verification

#### 5.1 Check Exporters
```bash
# Check if exporters are responding
curl http://localhost:9100/metrics  # Node Exporter
curl http://localhost:9221/metrics  # PVE Exporter
```

#### 5.2 Check Prometheus Targets
Go to `http://your-proxmox-ip:9090/targets` and verify all targets show as "UP"

#### 5.3 Test Queries in Prometheus
Try these queries in Prometheus:

- `up` - Shows which targets are up
- `node_cpu_seconds_total` - CPU metrics
- `pve_cpu_usage_ratio` - Proxmox CPU usage

## Maintenance
Update Prometheus
```bash
sudo systemctl stop prometheus
# Download new version from GitHub
cd /tmp
wget https://github.com/prometheus/prometheus/releases/download/vX.X.X/prometheus-X.X.X.linux-amd64.tar.gz
tar xvf prometheus-X.X.X.linux-amd64.tar.gz
sudo cp prometheus-X.X.X.linux-amd64/prometheus /usr/local/bin/
sudo chown prometheus:prometheus /usr/local/bin/prometheus
sudo systemctl start prometheus
```

Backup Grafana Dashboards
```bash
# Grafana dashboards are stored in database
sudo cp /var/lib/grafana/grafana.db /backup/location/grafana-$(date +%Y%m%d).db
```

### Quick Command Reference
Monitoring VM Commands
```bash
# Check all services
sudo systemctl status prometheus grafana-server pve_exporter node_exporter

# Restart services
sudo systemctl restart prometheus
sudo systemctl restart grafana-server
sudo systemctl restart pve_exporter

# View logs
sudo journalctl -u prometheus -f
sudo journalctl -u grafana-server -f
sudo journalctl -u pve_exporter -f
```

Proxmox Host Commands
```bash
# Check node_exporter
sudo systemctl status node_exporter

# View metrics
curl http://localhost:9100/metrics
```

### Useful URLs
After setup, bookmark these:

- Grafana: `http://monitoring-vm-ip:3000`
- Prometheus: `http://monitoring-vm-ip:9090`
- Prometheus Targets: `http://monitoring-vm-ip:9090/targets`
- Proxmox Host Metrics: `http://proxmox-ip:9100/metrics`
- PVE Exporter: `http://monitoring-vm-ip:9221/pve`