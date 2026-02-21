-- Migration: add partial index for process tree live query (faster ListProcessTree)
-- Safe to run on existing DBs (IF NOT EXISTS)
CREATE INDEX IF NOT EXISTS idx_process_tree_host_live ON process_tree(host_id, start_ts) WHERE exit_ts IS NULL;
