# EDR Platform Architecture — Production-Grade Design

## 1. System Architecture (Text-Based)

```
                                    ┌─────────────────────────────────────────────────────────────────┐
                                    │                        CLOUD / K8s CLUSTER                        │
                                    │                                                                   │
  ┌──────────────┐                  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
  │   AGENTS     │   mTLS/gRPC       │  │   INGEST    │───▶│ NORMALIZE   │───▶│   DETECTION ENGINE  │  │
  │  (50k EPs)   │──────────────────▶│  │   SERVICE   │    │   SERVICE   │    │  (Sigma + Custom)   │  │
  │              │   NATS / Direct   │  └─────────────┘    └─────────────┘    └──────────┬──────────┘  │
  └──────────────┘                  │         │                    │                     │             │
        │                            │         │                    │                     ▼             │
        │  execve, file, network      │         ▼                    ▼              ┌─────────────┐      │
        │  process tree state         │  ┌─────────────┐    ┌─────────────┐       │   ALERTS    │      │
        │  host inventory             │  │  ClickHouse │    │  PostgreSQL  │       │   SERVICE   │      │
        │                             │  │  (events)   │    │  (metadata)  │       └──────┬──────┘      │
        │                             │  └─────────────┘    └─────────────┘              │             │
        │                             │         │                    │                   ▼             │
        │                             │         │                    │            ┌─────────────┐      │
        │                             │         │                    │            │ IR DISPATCH │      │
        │                             │         │                    │            │  (commands) │      │
        │                             │         │                    │            └──────┬──────┘      │
        │                             │         │                    │                   │             │
        │                             │         │                    │                   ▼             │
        │                             │  ┌──────┴─────────────────────┴──────────────────┴──────┐      │
        │                             │  │                      NATS JetStream                   │      │
        │                             │  │  streams: events, alerts, ir_commands, rule_updates   │      │
        │                             │  └──────────────────────────────────────────────────────┘      │
        │                             │                                                                   │
        │                             │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐    │
        │◀────────────────────────────│  │   REDIS     │  │ RULE ENGINE │  │  WEB UI (Next.js)    │    │
        │  IR commands, rule updates  │  │  (cache)    │  │  (hot load) │  │  + API Gateway       │    │
        │                             │  └─────────────┘  └─────────────┘  └─────────────────────┘    │
        └─────────────────────────────┴─────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Breakdown

### Agent (Go + eBPF)
- **Event capture**: execve, file (openat/unlink/rename), network (connect/sendto/accept), privilege, exit, module load
- **Process tree cache**: in-memory map `pid → {ppid, exe, cmdline, start_ts}`; flushed on exit to backend
- **mTLS**: client cert per agent; server validates tenant + host identity
- **NATS**: publish to `events.{tenant}.{host_id}`; subscribe to `ir.{tenant}.{host_id}`, `rules.{tenant}`
- **Persistent connection**: gRPC stream or NATS core; heartbeat every 30s

### Backend Services

| Service | Responsibility | Scale |
|---------|----------------|-------|
| **Ingestion** | Receive events via NATS/gRPC, validate, publish to ClickHouse + NATS stream | 50k agents × ~100 ev/s = 5M ev/s → shard |
| **Normalize** | ECS-like schema, enrich (MITRE, GTFOBins), resolve host_id | Stateless, horizontal |
| **Detection** | Consume normalized events, evaluate Sigma + custom rules, emit alerts | Stateless, horizontal |
| **Rule Engine** | Store rules in Postgres, compile Sigma → JSON, push to Redis + NATS for hot-reload | Single + replica |
| **IR Dispatcher** | Receive IR commands, publish to `ir.{tenant}.{host_id}`, log to Postgres | Stateless |
| **Alerts** | Aggregate alerts, compute risk score, store in Postgres + ClickHouse | Stateless |

### Process Tree Engine
- **Storage**: ClickHouse `process_tree` table; materialized view per host for latest tree
- **Reconstruction**: On execve → insert node; on exit → mark `exited_at`; parent-child via `ppid`
- **PID reuse**: Use `(host_id, pid, start_ts)` as unique key; `start_ts` from execve event
- **Handling exit**: `exit_group` event → update `exited_at`; tree query filters `exited_at IS NULL` for live view

---

## 3. Folder Structure

```
edr-linux/
├── agent/                    # eBPF agent (evolved from cmd/edr-client)
│   ├── cmd/
│   │   └── agent/
│   │       └── main.go
│   ├── pkg/
│   │   ├── ebpf/             # eBPF loaders
│   │   ├── collector/        # event collection
│   │   ├── tree/             # local process tree cache
│   │   ├── transport/        # mTLS, NATS, gRPC
│   │   └── config/
│   ├── bpf/                  # eBPF C programs (existing)
│   └── Dockerfile
│
├── backend/
│   ├── cmd/
│   │   ├── ingest/           # ingestion service
│   │   ├── normalize/        # normalization service
│   │   ├── detection/        # detection engine
│   │   ├── rule-engine/     # Sigma compiler + hot-reload
│   │   ├── ir-dispatcher/    # IR command dispatcher
│   │   └── api/              # REST API gateway
│   ├── pkg/
│   │   ├── events/           # event schema, ECS-like
│   │   ├── sigma/            # Sigma compiler (YAML → JSON)
│   │   ├── detection/        # rule evaluation engine
│   │   ├── tree/             # process tree reconstruction
│   │   ├── risk/             # risk scoring
│   │   └── ir/               # IR command types
│   └── Dockerfile
│
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx              # Dashboard
│   │   │   ├── hosts/page.tsx        # Host inventory
│   │   │   ├── alerts/page.tsx       # Alerts
│   │   │   ├── process-tree/[id]/page.tsx  # Process tree viz
│   │   │   ├── rules/page.tsx        # Rule management
│   │   │   └── incidents/page.tsx    # IR actions
│   │   ├── components/
│   │   │   ├── ProcessTree/          # Hexagonal viz
│   │   │   ├── HostCard/
│   │   │   └── AlertTable/
│   │   └── lib/
│   ├── package.json
│   └── Dockerfile
│
├── deploy/
│   ├── docker-compose.yml    # Full stack
│   ├── docker-compose.dev.yml
│   └── .env.example
│
├── sigma/
│   └── rules/                # Sigma YAML rules (existing)
│
└── docs/
    ├── ARCHITECTURE.md       # This file
    ├── API.md
    └── SCHEMA.md
```

---

## 4. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **NATS JetStream** | Decouple ingestion from detection; replay for backfill; <3s latency with persistence |
| **ClickHouse for events** | Columnar, high insert rate, time-series queries; 50k hosts × 100 ev/s |
| **PostgreSQL for metadata** | Hosts, rules, alerts, IR logs; ACID, relational |
| **Redis for rule cache** | Hot-reload: detection engine subscribes to rule updates; no restart |
| **Sigma → JSON internal** | Compile once; streaming eval uses JSON conditions; no YAML parse at runtime |
| **Process tree in ClickHouse** | Append-only; `(host_id, pid, ppid, start_ts)`; materialized view for "current tree" |
| **mTLS per agent** | No shared secrets; cert = identity; tenant from cert CN/san |
| **Multi-tenant** | `tenant_id` in all tables; NATS subject `events.{tenant}.{host}` |

---

## 5. Example Internal Event Schema (ECS-like)

```json
{
  "@timestamp": "2026-02-15T12:34:56.789Z",
  "agent": {
    "id": "host-abc123",
    "name": "JIMBE",
    "hostname": "jimbe.prod.local",
    "tenant_id": "t1"
  },
  "event": {
    "type": "process_start",
    "category": "process",
    "action": "exec",
    "id": "ev-uuid-xxx",
    "ingested": "2026-02-15T12:34:56.790Z"
  },
  "process": {
    "pid": 153426,
    "ppid": 153425,
    "executable": "/usr/bin/ip",
    "command_line": "ip addr show",
    "name": "ip",
    "start": "2026-02-15T12:34:56.789Z",
    "hash": { "sha256": "abc123..." },
    "parent": {
      "pid": 153425,
      "executable": "/usr/bin/xfce4-panel",
      "command_line": "xfce4-panel --gen"
    }
  },
  "user": { "id": "1000", "name": "jim", "group": { "id": "1000" } },
  "host": { "hostname": "jimbe", "os": { "platform": "linux" } },
  "threat": {
    "mitre": ["T1005", "T1059"],
    "gtfobins": ["file-read", "shell"]
  }
}
```

---

## 6. Example Rule Internal Format (JSON)

```json
{
  "id": "proc-lnx-netcat-revshell",
  "name": "Suspicious Netcat Reverse Shell",
  "severity": "high",
  "enabled": true,
  "sigma_source": "process_suspicious_netcat.yml",
  "conditions": {
    "op": "or",
    "children": [
      {
        "op": "and",
        "children": [
          { "field": "process.command_line", "op": "contains", "value": " -e " },
          { "field": "process.executable", "op": "endswith", "value": "/nc" }
        ]
      },
      {
        "op": "and",
        "children": [
          { "field": "process.command_line", "op": "contains", "value": " -e " },
          { "field": "process.executable", "op": "endswith", "value": "ncat" }
        ]
      }
    ]
  },
  "mitre": ["T1059"],
  "tags": ["attack.execution"]
}
```

---

## 7. Example API Spec

```
# Hosts
GET    /api/v1/hosts                    # List hosts (paginated, filter by tenant)
GET    /api/v1/hosts/{id}               # Host detail + risk score
GET    /api/v1/hosts/{id}/process-tree  # Process tree for host
GET    /api/v1/hosts/{id}/inventory     # Software, kernel, etc.

# Alerts
GET    /api/v1/alerts                   # List alerts (filter: host, severity, time)
GET    /api/v1/alerts/{id}              # Alert detail
POST   /api/v1/alerts/{id}/acknowledge  # Ack alert

# Rules
GET    /api/v1/rules                    # List rules
POST   /api/v1/rules                     # Create/upload rule (Sigma YAML)
PUT    /api/v1/rules/{id}               # Update rule
DELETE /api/v1/rules/{id}               # Delete rule
POST   /api/v1/rules/{id}/enable        # Enable
POST   /api/v1/rules/{id}/disable       # Disable

# IR Actions
POST   /api/v1/hosts/{id}/isolate       # Isolate host
POST   /api/v1/hosts/{id}/release       # Release from isolation
POST   /api/v1/hosts/{id}/kill-process  # Body: { "pid": 12345 }
POST   /api/v1/hosts/{id}/collect       # Body: { "paths": ["/tmp"], "artifact": "triage" }
GET    /api/v1/ir/actions               # List IR actions (audit log)
```

---

## 8. Example IR Command Payload

```json
{
  "id": "ir-cmd-uuid-123",
  "tenant_id": "t1",
  "host_id": "host-abc123",
  "action": "isolate",
  "params": {},
  "requested_by": "admin@corp.com",
  "requested_at": "2026-02-15T12:35:00Z",
  "status": "pending"
}
```

```json
{
  "id": "ir-cmd-uuid-124",
  "action": "kill_process",
  "params": { "pid": 153426, "signal": "SIGKILL" }
}
```

```json
{
  "id": "ir-cmd-uuid-125",
  "action": "collect_triage",
  "params": {
    "paths": ["/tmp", "/var/log"],
    "artifact_name": "incident-20260215-001",
    "max_size_mb": 500
  }
}
```

---

## 9. Process Tree Engine Design

### Storage (ClickHouse)

```sql
CREATE TABLE process_nodes (
  tenant_id String,
  host_id String,
  pid UInt32,
  ppid UInt32,
  exe String,
  cmdline String,
  start_ts DateTime64(3),
  exit_ts Nullable(DateTime64(3)),
  uid UInt32,
  gid UInt32,
  sha256 String,
  mitre Array(String),
  gtfobins Array(String)
) ENGINE = ReplacingMergeTree(exit_ts)
PARTITION BY toYYYYMM(start_ts)
ORDER BY (tenant_id, host_id, pid, start_ts);
```

- **PID reuse**: `(host_id, pid, start_ts)` unique; ReplacingMergeTree uses `exit_ts` for dedup.
- **Exit**: On `exit_group` event, insert same row with `exit_ts = now()`.
- **Query live tree**: `WHERE exit_ts IS NULL`.

### Local Agent Cache
- Map: `pid → {ppid, exe, cmdline, start_ts}`.
- On execve: insert.
- On exit: remove; optionally send batch to backend for persistence.
- Max size: 100k entries per host; evict oldest on overflow.

---

## 10. Sigma Integration Design

1. **Compile**: Sigma YAML → internal JSON (conditions, field mappings).
2. **Store**: Postgres `rules` table; Redis key `rules:{tenant}` = JSON array.
3. **Deploy**: Rule engine publishes to NATS `rules.update.{tenant}`; detection engine subscribes, reloads from Redis.
4. **Streaming eval**: For each event, iterate rules; evaluate conditions against event JSON; on match → emit alert.

---

## 11. Risk Scoring Design

```
score = base_score × mitre_mult × recency_decay

base_score = Σ (alert_severity_weight × count) / max_alerts_per_host
  severity: critical=10, high=5, medium=2, low=1

mitre_mult = 1 + (0.1 × unique_mitre_techniques_in_last_24h)

recency_decay = 1.0 if last_alert < 1h else 0.8 if < 24h else 0.5
```

---

## 12. Host Isolation Implementation

- **Agent**: On `ir.isolate` command, enable iptables/nftables DROP all except loopback + management IP.
- **Management IP**: From config or cert; allow NATS/gRPC to server.
- **Release**: On `ir.release`, flush rules, restore normal routing.
