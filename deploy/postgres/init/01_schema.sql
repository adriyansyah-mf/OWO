-- EDR Platform - PostgreSQL schema
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hosts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  hostname TEXT NOT NULL,
  agent_name TEXT,
  last_seen TIMESTAMPTZ DEFAULT NOW(),
  risk_score FLOAT DEFAULT 0,
  status TEXT DEFAULT 'online',
  os TEXT,
  kernel TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(tenant_id, hostname)
);

CREATE TABLE IF NOT EXISTS rules (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  sigma_id TEXT,
  name TEXT NOT NULL,
  severity TEXT NOT NULL,
  enabled BOOLEAN DEFAULT true,
  sigma_yaml TEXT,
  compiled_json JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  host_id TEXT NOT NULL REFERENCES hosts(id),
  rule_id UUID REFERENCES rules(id),
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT,
  event_json JSONB,
  mitre TEXT[],
  acknowledged BOOLEAN DEFAULT false,
  acknowledged_at TIMESTAMPTZ,
  acknowledged_by TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ir_actions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  host_id TEXT NOT NULL REFERENCES hosts(id),
  action TEXT NOT NULL,
  params JSONB,
  status TEXT DEFAULT 'pending',
  requested_by TEXT,
  requested_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  result TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ir_host ON ir_actions(host_id);

CREATE TABLE IF NOT EXISTS process_tree (
  id SERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  pid INT NOT NULL,
  ppid INT,
  exe TEXT,
  cmdline TEXT,
  start_ts TIMESTAMPTZ DEFAULT NOW(),
  exit_ts TIMESTAMPTZ,
  uid INT,
  sha256 TEXT,
  mitre TEXT[],
  gtfobins TEXT[]
);

CREATE INDEX IF NOT EXISTS idx_process_tree_host ON process_tree(host_id);
CREATE INDEX IF NOT EXISTS idx_process_tree_ts ON process_tree(host_id, start_ts);

INSERT INTO tenants (id, name) VALUES ('default', 'Default') ON CONFLICT (id) DO NOTHING;
