-- EDR Platform - ClickHouse schema
CREATE DATABASE IF NOT EXISTS edr;

CREATE TABLE IF NOT EXISTS edr.events (
  tenant_id String,
  host_id String,
  event_id String,
  event_type String,
  timestamp DateTime64(3),
  process_pid UInt32,
  process_ppid UInt32,
  process_exe String,
  process_cmdline String,
  process_name String,
  user_id UInt32,
  user_name String,
  hostname String,
  sha256 String,
  mitre Array(String),
  gtfobins Array(String),
  raw JSON
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, host_id, timestamp)
TTL timestamp + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS edr.process_tree (
  tenant_id String,
  host_id String,
  pid UInt32,
  ppid UInt32,
  exe String,
  cmdline String,
  start_ts DateTime64(3),
  exit_ts Nullable(DateTime64(3)),
  uid UInt32,
  sha256 String,
  mitre Array(String),
  gtfobins Array(String)
) ENGINE = ReplacingMergeTree(exit_ts)
PARTITION BY toYYYYMM(start_ts)
ORDER BY (tenant_id, host_id, pid, start_ts);
