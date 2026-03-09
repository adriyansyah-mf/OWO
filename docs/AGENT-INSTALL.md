# OWO EDR — Agent Installation Guide

This guide covers how to install, configure, and manage the `edr-client` agent on Linux endpoints.

---

## Requirements

| Requirement | Details |
|---|---|
| OS | Linux (Debian/Ubuntu/Kali/Pop/Mint, RHEL/CentOS/Fedora/Rocky/Alma) |
| Architecture | `amd64` (x86_64) or `arm64` (aarch64) |
| Kernel | >= 5.x with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`) |
| Privileges | Must run as **root** (eBPF requires root) |
| NATS | Reachable NATS server (deployed with backend stack) |

### Verify kernel BTF support

```bash
ls /sys/kernel/btf/vmlinux
# should exist — if not, upgrade your kernel
```

---

## Quick Install (one-liner)

The installer auto-detects OS, downloads the correct package (`.deb` or `.rpm`), configures, and starts the agent.

```bash
curl -fsSL https://github.com/adriyansyah-mf/OWO/releases/latest/download/install.sh | sudo NATS_URL=nats://192.168.1.3:4222 sh
```

> Replace `192.168.1.3` with the IP of your backend server running NATS.

### With tenant and group label

```bash
curl -fsSL https://github.com/adriyansyah-mf/OWO/releases/latest/download/install.sh | \
  sudo NATS_URL=nats://192.168.1.3:4222 \
       TENANT_ID=acme \
       EDR_GROUP=servers \
       sh
```

---

## Installer Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NATS_URL` | `nats://127.0.0.1:4222` | NATS server URL the agent connects to |
| `TENANT_ID` | `default` | Tenant/org identifier for multi-tenant deployments |
| `EDR_GROUP` | *(empty)* | Group label for this agent (e.g. `servers`, `workstations`) |
| `EDR_VERSION` | `latest` | Package version to install (e.g. `v0.1.9`) |
| `RELEASE_URL` | GitHub releases URL | Override for air-gapped/internal mirror |
| `SKIP_START` | `0` | Set to `1` to install but not start the service |

### Install specific version without starting

```bash
curl -fsSL https://github.com/adriyansyah-mf/OWO/releases/latest/download/install.sh | \
  sudo EDR_VERSION=v0.1.9 SKIP_START=1 sh
```

---

## Manual Package Install

### Debian / Ubuntu / Kali

```bash
# Download .deb
wget https://github.com/adriyansyah-mf/OWO/releases/download/v0.1.9/edr-client_0.1.9_amd64.deb

# Install
sudo dpkg -i edr-client_0.1.9_amd64.deb
```

### RHEL / CentOS / Fedora / Rocky

```bash
# Download .rpm
wget https://github.com/adriyansyah-mf/OWO/releases/download/v0.1.9/edr-client_0.1.9_amd64.rpm

# Install
sudo rpm -Uvh edr-client_0.1.9_amd64.rpm
```

---

## Files Installed

| Path | Description |
|---|---|
| `/usr/bin/edr-client` | Agent binary |
| `/etc/edr/edr.yaml` | Main configuration file |
| `/etc/edr/env` | Environment overrides (sourced by systemd) |
| `/usr/lib/edr/bpf/` | Compiled eBPF object files (`.o`) |
| `/usr/lib/edr/sigma/rules/` | Sigma detection rules directory |
| `/usr/lib/edr/contrib/gtfobins.json` | GTFOBins enrichment data |
| `/etc/systemd/system/edr-client.service` | systemd unit |
| `/var/log/edr/` | Log directory |
| `/var/lib/edr/` | State directory (DLP policies, quarantine) |

---

## Configuration

The main config file is `/etc/edr/edr.yaml`. Edit it before or after installation.

```yaml
agent:
  name: ""          # auto-detected (hostname) if empty
  hostname: ""      # override reported hostname
  group: "servers"  # agent group label (optional)

output:
  file:
    enabled: true
    path: "/var/log/edr/events.jsonl"
  stderr: false     # dev only — set true to print events to console
  nats:
    enabled: true
    url: "nats://10.0.0.1:4222"    # ← your NATS server
    subject: "events.default"
    tenant_id: "default"           # ← your tenant ID

monitor:
  execve: true              # process execution (execve) — recommended ON
  file_events: true         # openat/unlink/rename on watched paths
  network_events: true      # outbound/inbound connections
  privilege_events: true    # setuid/setgid/setreuid/setregid
  exit_events: true         # process exit
  module_events: true       # kernel module loads (insmod/modprobe)
  write_events: false       # write() syscall — noisy, enable for Device Control
  process_events: false     # fork/clone — very noisy, disable unless needed
  file_watch_all_paths: false  # true = all paths; false = /etc,/usr/bin,/bin,/tmp,/dev/shm
  realtime_av_scan: false   # ClamAV scan on every execve — adds latency
  sigma_rules_path: "/usr/lib/edr/sigma/rules"
  gtfobins_path: "/usr/lib/edr/contrib/gtfobins.json"
  clamav_scan_paths:
    - "/tmp"
    - "/var/tmp"
    - "/home"
  dlp_scan_paths:
    - "/tmp"
    - "/var/tmp"
    - "/home"
  process_snapshot_interval: 60  # seconds; 0 = disable periodic process list

logging:
  level: warn   # debug | info | warn | error
```

### Environment overrides (`/etc/edr/env`)

Values in `/etc/edr/env` are sourced by systemd and override the config. Useful for secrets or environment-specific values without editing YAML.

```bash
NATS_URL=nats://10.0.0.1:4222
```

---

## Service Management

```bash
# Start
sudo systemctl start edr-client

# Stop
sudo systemctl stop edr-client

# Restart (e.g. after config change)
sudo systemctl restart edr-client

# Enable auto-start on boot
sudo systemctl enable edr-client

# Disable auto-start
sudo systemctl disable edr-client

# Check status
sudo systemctl status edr-client

# View live logs
sudo journalctl -u edr-client -f

# View last 100 log lines
sudo journalctl -u edr-client -n 100
```

---

## Verify Agent is Working

After starting, verify the agent is sending events:

```bash
# Check service is active
systemctl is-active edr-client

# Tail event log
tail -f /var/log/edr/events.jsonl

# Trigger a test event (execute something)
ls /tmp
# You should see an execve event in the log
```

On the dashboard, navigate to **All Endpoints** — the host should appear within ~60 seconds.

---

## Sigma Rules

Rules are stored in `/usr/lib/edr/sigma/rules/` and hot-reload automatically when pushed from the dashboard.

To add a rule manually:

```bash
# Copy a rule file
sudo cp my-rule.yml /usr/lib/edr/sigma/rules/

# Restart to reload (or wait for file watcher — polls every 30s)
sudo systemctl restart edr-client
```

Rules pushed via the **Sigma Rules** dashboard page are automatically distributed to all connected agents via NATS without a restart.

---

## DLP Configuration (Enterprise)

To enable behavioral DLP monitoring:

```yaml
ndlp:
  enable_behavioral: true
  policy_cache_path: "/var/lib/edr/dlp/policies.json"
  audit_log_path: "/var/log/edr/dlp-audit.jsonl"
  quarantine_dir: "/var/lib/edr/dlp/quarantine"
  channels:
    - usb
    - local_file
    - network_upload
  behavioral_thresholds:
    mass_access_per_minute: 100   # file opens/min before alert
    bulk_read_mb: 50              # MB read/min before alert
    usb_copy_per_minute: 20       # USB writes/min before alert
```

---

## Uninstall

```bash
# Debian/Ubuntu
sudo systemctl stop edr-client
sudo systemctl disable edr-client
sudo dpkg -r edr-client

# RHEL/CentOS/Fedora
sudo systemctl stop edr-client
sudo systemctl disable edr-client
sudo rpm -e edr-client

# Remove config and data (optional — destructive)
sudo rm -rf /etc/edr /var/log/edr /var/lib/edr /usr/lib/edr
```

---

## Troubleshooting

### Agent fails to start — eBPF error

```
failed to load eBPF: operation not permitted
```

**Cause:** Not running as root, or kernel lacks BTF.

```bash
# Check BTF
ls /sys/kernel/btf/vmlinux

# Check capabilities
id   # must be root (uid=0)
```

---

### Agent starts but no events appear in dashboard

1. Verify NATS URL is reachable from the agent host:
   ```bash
   curl -s nats://10.0.0.1:8222/varz | grep version
   # or
   nc -zv 10.0.0.1 4222
   ```
2. Check logs for NATS connection errors:
   ```bash
   journalctl -u edr-client -n 50 | grep -i nats
   ```
3. Ensure `output.nats.enabled: true` in `/etc/edr/edr.yaml`.

---

### High CPU usage

- Disable `write_events: false` (very noisy on active systems)
- Disable `process_events: false` (fork/clone fires on every process)
- Increase `logging.level: warn` (reduce log I/O)
- Disable `realtime_av_scan: false`

---

### Kernel module load errors

```
failed to attach tracepoint: no such file or directory
```

**Cause:** Kernel does not have the specific tracepoint. Try disabling the affected monitor option in config.

---

## Build from Source

If a pre-built package is not available for your distribution:

```bash
# Install build dependencies (Debian/Ubuntu)
sudo apt install clang llvm linux-headers-$(uname -r) golang-go make

# Clone and build
git clone https://github.com/adriyansyah-mf/OWO.git
cd OWO
make

# Run
sudo ./bin/edr-client -config config.production.yaml
```

See the main [README](../README.md) for full build instructions.
