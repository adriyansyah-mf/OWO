# EDR Platform — Docker Deploy

## Quick Start (Infrastructure Only)

```bash
cd deploy
docker compose -f docker-compose.infra.yml up -d
```

Services:
- **NATS** (4222, 8222) — message bus
- **ClickHouse** (8123, 9000) — event storage
- **PostgreSQL** (5432) — metadata
- **Redis** (6379) — cache

## Full Stack (Backend + Infra)

```bash
cd deploy
docker compose -f docker-compose.yml up -d --build
```

Services:
- ingest, normalize, detection, ir-dispatcher, api
- NATS, ClickHouse, Postgres, Redis

Ports:
- **80** — UI + API (nginx reverse proxy)
- **4222** — NATS (untuk EDR agent)

## Akses UI

Setelah `docker compose up -d`, buka: **http://localhost**

**Login default:** `owo` / `owo`

Dashboard, Hosts, Alerts, Process Tree tersedia. Data dari EDR agent yang terhubung ke NATS akan muncul di sini.

## Konfigurasi EDR Agent

Agar data dari agent masuk ke server dan fitur IR (Isolate, Kill, Collect) berfungsi, edit `config.yaml` atau `config.production.yaml`:

```yaml
output:
  nats:
    enabled: true
    url: "nats://<IP-SERVER>:4222"   # Lihat tabel di bawah
    subject: "events.default"
    tenant_id: "default"

agent:
  hostname: "nama-host-ini"   # Harus unik per host; dipakai sebagai host_id di UI
```

| Agent dijalankan di | NATS URL |
|---------------------|----------|
| **Host yang sama** dengan Docker stack | `nats://127.0.0.1:4222` |
| **Mesin lain** (server Docker di 192.168.1.10) | `nats://192.168.1.10:4222` |
| **Docker Desktop** (agent di host) | `nats://host.docker.internal:4222` atau `nats://127.0.0.1:4222` |

Jalankan agent: `sudo ./edr-client -config config.yaml`

**Fitur yang tersedia saat NATS aktif:**
- **Events** → execve, file, network, exit, dll. dikirim ke server
- **Process Tree** → tampil di UI per host
- **Alerts** → dari Sigma rules
- **IR Actions** (dari Web UI):
  - **Isolate** → iptables DROP (host terisolasi dari jaringan)
  - **Release** → kembalikan jaringan
  - **Kill** → SIGKILL proses (dari Process Tree)
  - **Collect** → tar /tmp, /var/log ke triage

## Run Locally (no Docker)

```bash
# Terminal 1: NATS
docker run -p 4222:4222 -p 8222:8222 nats:2.10-alpine -js -m 8222

# Terminal 2-6: Backend
./bin/ingest &
./bin/normalize &
./bin/detection &
./bin/ir-dispatcher &
./bin/api &

# Agent with NATS (edit config.yaml: output.nats.enabled: true)
sudo ./bin/edr-client -config config.yaml
```

## Test Pipeline (Tanpa Agent)

Untuk verifikasi bahwa detection + alerts bekerja, inject event test:

```bash
# Via curl (setelah login, ambil token dari localStorage)
curl -X POST http://localhost:8080/api/v1/test/inject-event \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json"

# Atau via script
cd .. && go run scripts/inject_test_event.go
```

Lalu cek **Threat Alerts** di UI — harus muncul "Netcat Reverse Shell (nc -e)" dalam beberapa detik.

## Agent: Kurangi noise di console

Dengan `config.production.yaml` (atau `output.file.enabled` / `output.nats.enabled`), event stream ke stderr otomatis dimatikan. Jika masih berisik, pastikan `output.stderr: false` di config.

## Process tree: snapshot periodik (bukan per-execve)

Process tree sekarang pakai **snapshot periodik** (seperti `ps aux`) setiap 60 detik — tidak simpan tiap execve. Hemat storage.

Config: `monitor.process_snapshot_interval: 60` (detik). Event execve tetap dikirim untuk **detection** (Sigma rules), tapi tidak disimpan ke process_tree.

## Process tree lemot

Sudah dioptimasi: API limit 300 proses, index DB, UI incremental load (80 grid / 120 hex awal, tombol "Show more").

**DB existing** (sebelum migration): jalankan index untuk percepat query:
```bash
docker exec -i deploy-postgres-1 psql -U edr -d edr -c "CREATE INDEX IF NOT EXISTS idx_process_tree_host_live ON process_tree(host_id, start_ts) WHERE exit_ts IS NULL;"
```
(Ganti `deploy-postgres-1` dengan nama container postgres Anda.)

## Troubleshooting: Test inject OK, tapi nc -e tidak terdetek

Jika `go run scripts/inject_test_event.go` menghasilkan alert, tapi `nc -e /bin/sh 127.0.0.1 4444` tidak:

1. **Agent harus jalan** di host yang sama:
   ```bash
   sudo ./edr-client -config config.production.yaml
   ```
   Harus ada log: `NATS output: events.default (tenant=default)`. Jika ada "NATS output disabled", cek NATS URL.

2. **Cek ingest terima execve** saat nc dijalankan:
   ```bash
   # Terminal 1: agent
   sudo ./edr-client -config config.production.yaml

   # Terminal 2: nc
   nc -e /bin/sh 127.0.0.1 4444

   # Terminal 3: log ingest
   docker compose -f deploy/docker-compose.yml logs ingest --tail 30
   ```
   Harus muncul `ingest: JIMBE execve pid=...`. Jika tidak ada → agent tidak mengirim ke NATS.

3. **NATS URL**: Agent di host = `nats://127.0.0.1:4222`. Pastikan Docker expose port 4222.

## Troubleshooting: lookup nats ... no such host

Jika detection/ingest/normalize gagal konek ke NATS (`no such host`), pastikan **seluruh stack** jalan:

```bash
cd deploy && docker compose -f docker-compose.yml up -d
```

Jangan start container satu per satu — NATS harus jalan dulu (detection punya `depends_on: nats`).

## Troubleshooting: Agent tidak muncul di UI

1. **Cek Docker stack jalan**: `docker compose -f docker-compose.yml ps` — semua service harus `Up`
2. **Cek NATS port terbuka**: `nc -zv localhost 4222` (atau IP server)
3. **Cek log agent** saat start:
   - `NATS output: events.default (tenant=default)` → konek OK
   - `nats connect: ... (NATS output disabled)` → URL salah / NATS tidak reachable
4. **NATS URL**:
   - Agent di **host yang sama** dengan Docker: `nats://127.0.0.1:4222`
   - Agent di **mesin lain**: ganti dengan IP server yang jalankan Docker
5. **File output gagal** (permission denied): Agent tetap kirim ke NATS. Bisa nonaktifkan `output.file.enabled: false` untuk testing.

## Development (tanpa Docker)

- **Next.js**: `cd frontend && npm install && npm run dev` → http://localhost:3000 (API di http://localhost:8080)
